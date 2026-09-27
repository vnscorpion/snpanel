// The MCP addon, end to end: the protocol, who sees which tools, every tool
// against a real website, the guards, the audit log and the tokens' life.
//
//     node mcp.mjs [out-dir]
//
// Runs on the box, as root: it reads the panel's database for a token's
// expiry and makes requests to a site through nginx. Makes a user of its own,
// `mcpcheck`, with a site, and removes them and everything it made at the
// end; the addon is left installed or not as it was found.
import { chromium, request as playwrightRequest } from 'playwright';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/mcp';
mkdirSync(OUT, { recursive: true });
const NAME = 'mcpcheck';
const PASSWORD = 'mcp check password 12';
const DOMAIN = `mcp${Date.now() % 1000000}.example.com`;
const ENDPOINT = `${BASE}/api/mcp`;

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dbFile = (readFileSync('/opt/snpanel/backend/.env', 'utf8').match(/^DATABASE_URL=sqlite:\/\/\/?(.*)$/m) || [])[1];
const sql = (statement, ...params) => run('python3', ['-c', 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2], sys.argv[3:]).fetchall(); c.commit(); print(r)', dbFile, statement, ...params.map(String)]).trim();

const browser = await chromium.launch();
async function session(username, password) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US' });
  await context.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
  if (username) {
    const res = await context.request.post(`${BASE}/api/auth/login`, { form: { username, password } });
    if (res.status() !== 200) throw new Error(`login as ${username}: ${res.status()}`);
  } else {
    await logIn(context);
  }
  const csrf = async () => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
  const api = async (method, path, data) => context.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': await csrf() }, timeout: 600000 });
  return { context, api };
}
const json = async (res) => res.json().catch(() => ({}));

// A bare client: no cookies, only what an assistant sends.
const client = await playwrightRequest.newContext({ ignoreHTTPSErrors: true });
let nextId = 1;
async function rpc(token, body, headers = {}) {
  const res = await client.post(ENDPOINT, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
    data: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)),
  });
  const text = await res.text();
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch {}
  return { status: res.status(), headers: res.headers(), body: parsed, text };
}
const call = async (token, method, params) => (await rpc(token, { jsonrpc: '2.0', id: nextId++, method, params })).body;
async function tool(token, name, args = {}) {
  const reply = await call(token, 'tools/call', { name, arguments: args });
  if (reply?.error) return { rpcError: reply.error };
  const text = reply?.result?.content?.[0]?.text ?? '';
  let data = null;
  try { data = JSON.parse(text); } catch {}
  return { isError: !!reply?.result?.isError, text, data };
}

const admin = await session();
const addonsBefore = await json(await admin.api('GET', '/addons'));
const wasInstalled = !!addonsBefore.items?.find((a) => a.slug === 'mcp')?.installed;
let userId = null;
let siteId = null;
let scheduleId = null;
const tokens = [];
try {
  // ---------------------------------------------------------------- setup
  if (!wasInstalled) await admin.api('POST', '/addons/mcp/install');
  const old = (await json(await admin.api('GET', '/users?usage=0'))).find((u) => u.username === NAME);
  if (old) await admin.api('DELETE', `/users/${old.id}`);
  userId = (await json(await admin.api('POST', '/users', { username: NAME, email: `${NAME}@example.com`, password: PASSWORD, role: 'end_user', website_limit: 2, storage_limit_mb: 500 }))).id;
  const site = await json(await admin.api('POST', '/websites', { domain: DOMAIN, app_type: 'static', owner_id: userId }));
  siteId = site.id;
  check(userId && siteId, `a user with a site (${DOMAIN})`);
  // Traffic for the logs: pages, a login page and a scanner - once the new
  // site's vhost answers and logs, which is after nginx's reload.
  const siteLog = `/var/log/nginx/${DOMAIN}.access.log`;
  for (let i = 0; i < 40; i++) {
    run('curl', ['-s', '-o', '/dev/null', '-H', `Host: ${DOMAIN}`, 'http://127.0.0.1/warm-up']);
    await sleep(500);
    if (run('cat', [siteLog]).includes('/warm-up')) break;
  }
  for (let i = 0; i < 6; i++) run('curl', ['-s', '-o', '/dev/null', '-H', `Host: ${DOMAIN}`, '-A', 'Mozilla/5.0 checker', `http://127.0.0.1/?page=${i}`]);
  for (let i = 0; i < 4; i++) run('curl', ['-s', '-o', '/dev/null', '-H', `Host: ${DOMAIN}`, '-A', 'EvilScanner/1.0', 'http://127.0.0.1/wp-login.php']);

  // ---------------------------------------------------------------- tokens from the page
  const page = await admin.context.newPage();
  const consoleErrors = [];
  page.on('console', (m) => { if (m.type() === 'error' && !/jobs\/latest/.test(m.location()?.url || '')) consoleErrors.push(m.text()); });
  page.on('dialog', (d) => d.accept());
  await page.goto(`${BASE}/ai-assistants`, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { level: 2, name: 'AI assistants (MCP)' }).waitFor();
  await page.getByLabel('Name', { exact: true }).fill('e2e admin');
  await page.getByLabel('Expires after').selectOption('30');
  await page.getByLabel('Allow actions').check();
  await page.getByRole('button', { name: 'Create token' }).click();
  await page.getByText('Token e2e admin is ready').waitFor({ timeout: 30000 });
  const adminToken = (await page.locator('pre[aria-labelledby="mcp-token"]').innerText()).trim();
  const claudeLine = await page.locator('pre[aria-labelledby="mcp-claude"]').innerText();
  check(/^snmcp_[A-Za-z0-9_-]{43}$/.test(adminToken), 'the page makes a token and shows it once');
  check(claudeLine.includes('claude mcp add --transport http snpanel') && claudeLine.includes(`Bearer ${adminToken}`), 'with the Claude Code command filled in');
  await page.screenshot({ path: `${OUT}/token-made-light-en.png`, fullPage: true });
  const stored = sql('select token_hash, prefix from mcp_tokens where name = ?', 'e2e admin');
  check(!stored.includes(adminToken) && stored.includes(adminToken.slice(0, 12)), 'only the hash and the first twelve characters are stored');
  await page.reload({ waitUntil: 'networkidle' });
  check(!(await page.locator('body').innerText()).includes(adminToken), 'and it is never shown again');

  const user = await session(NAME, PASSWORD);
  const make = async (who, name, canWrite) => {
    const made = await json(await who.api('POST', '/mcp/tokens', { name, can_write: canWrite, expires_days: 30 }));
    tokens.push(made.id);
    return made.token;
  };
  const userRead = await make(user, 'e2e user read', false);
  const userWrite = await make(user, 'e2e user write', true);
  const adminRead = await make(admin, 'e2e admin read', false);

  // ---------------------------------------------------------------- the protocol
  let r = await rpc(null, { jsonrpc: '2.0', id: 1, method: 'ping' });
  check(r.status === 401 && /Bearer realm="snpanel-mcp"/.test(r.headers['www-authenticate'] || ''), `no token: 401 with the realm (${r.status})`);
  r = await rpc('snmcp_notarealtoken', { jsonrpc: '2.0', id: 1, method: 'ping' });
  check(r.status === 401, 'an unknown token: 401');
  r = await rpc(adminToken, { jsonrpc: '2.0', id: 1, method: 'ping' }, { Origin: 'https://evil.example.com' });
  check(r.status === 403, `a request from another site's page: 403 (${r.status})`);
  const getRes = await client.get(ENDPOINT, { headers: { Authorization: `Bearer ${adminToken}` } });
  check(getRes.status() === 405 && getRes.headers().allow === 'POST', 'GET: 405, Allow: POST');
  r = await rpc(adminToken, '{not json');
  check(r.status === 400 && r.body?.error?.code === -32700, `a body that is not JSON: 400 and -32700 (${r.status} ${r.text.slice(0, 120)})`);
  let reply = await call(adminToken, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '1' } });
  check(reply?.result?.protocolVersion === '2025-06-18' && reply.result.serverInfo?.name === 'snpanel' && reply.result.capabilities?.tools, 'initialize answers the version asked for');
  reply = await call(adminToken, 'initialize', { protocolVersion: '1999-01-01' });
  check(reply?.result?.protocolVersion === '2025-06-18', 'and the newest for one it does not speak');
  r = await rpc(adminToken, { jsonrpc: '2.0', method: 'notifications/initialized' });
  check(r.status === 202 && !r.text, 'a notification: 202 and no body');
  r = await rpc(adminToken, [{ jsonrpc: '2.0', id: 'a', method: 'ping' }, { jsonrpc: '2.0', method: 'notifications/initialized' }]);
  check(Array.isArray(r.body) && r.body.length === 1 && r.body[0].id === 'a', 'a batch answers its requests only');
  reply = await call(adminToken, 'nope/nothing');
  check(reply?.error?.code === -32601, 'an unknown method: -32601');

  const count = async (token) => (await call(token, 'tools/list'))?.result?.tools?.length;
  check(await count(userRead) === 13 && await count(userWrite) === 20 && await count(adminRead) === 20 && await count(adminToken) === 32,
    'tools/list: 13 and 20 for a user, 20 and 32 for an administrator');
  const listed = (await call(adminToken, 'tools/list')).result.tools;
  const del = listed.find((t) => t.name === 'delete_file');
  check(del?.annotations?.destructiveHint === true && del.annotations.readOnlyHint === false && del.inputSchema.additionalProperties === false, 'delete_file is marked destructive, its schema closed');
  let out = await tool(userRead, 'write_file', { domain: DOMAIN, path: 'public_html/x.txt', content: 'x' });
  check(out.rpcError?.message === 'Unknown tool: write_file', 'a read-only token cannot even see write_file');
  out = await tool(userWrite, 'list_users');
  check(out.rpcError?.message === 'Unknown tool: list_users', "an administrator's tool is unknown to a user");
  out = await tool(adminToken, 'read_site_log', { domain: DOMAIN, lines: 5000 });
  check(out.rpcError?.code === -32602 && /at most 500/.test(out.rpcError.message), `arguments are checked (${out.rpcError?.message})`);
  out = await tool(adminToken, 'whoami', { extra: 1 });
  check(out.rpcError?.message === 'Unknown argument: extra', 'and nothing beyond them is taken');

  // ---------------------------------------------------------------- a user's tools
  out = await tool(userRead, 'whoami');
  check(out.data?.username === NAME && out.data.token.allows_actions === false, 'whoami names the account and what the token may do');
  out = await tool(userRead, 'list_websites');
  check(out.data?.count === 1 && out.data.websites[0].domain === DOMAIN && !out.text.includes('password'), 'a user lists only their own website, and no password');
  out = await tool(userRead, 'list_websites', { owner: 'admin' });
  check(out.isError && /Only an administrator/.test(out.text), 'and cannot name another account');
  const adminSite = (await tool(adminToken, 'list_websites')).data.websites.find((s) => s.owner !== NAME);
  if (adminSite) {
    out = await tool(userRead, 'get_website', { domain: adminSite.domain });
    check(out.isError && out.text === `No website ${adminSite.domain} on this account`, "somebody else's website reads as missing");
  }
  out = await tool(userRead, 'get_website', { domain: DOMAIN });
  check(out.data?.domain === DOMAIN && Array.isArray(out.data.aliases) && 'certificate' in out.data, 'get_website');
  out = await tool(userRead, 'list_databases');
  check(Array.isArray(out.data?.databases) && !out.text.includes('password'), 'list_databases, without passwords');
  out = await tool(userRead, 'read_site_log', { domain: DOMAIN, kind: 'access', lines: 20 });
  check(!out.isError && out.text.includes('wp-login.php'), `read_site_log (${out.text.slice(0, 80)})`);
  out = await tool(userRead, 'server_resources');
  check(!out.isError && out.data, 'server_resources');
  out = await tool(userRead, 'list_backup_jobs');
  check(!out.isError, 'list_backup_jobs');

  // Files, all the way round.
  out = await tool(userWrite, 'write_file', { domain: DOMAIN, path: 'public_html/mcp-e2e/deep/note.txt', content: 'first line\nNeedle in the second line\nthird' });
  check(!out.isError && out.data.folders_created.length === 2, `write_file makes the folders it needs (${out.text.slice(0, 120)})`);
  out = await tool(userWrite, 'read_file', { domain: DOMAIN, path: 'public_html/mcp-e2e/deep/note.txt', start_line: 2, line_count: 1 });
  check(out.data?.content === 'Needle in the second line' && out.data.total_lines === 3 && out.data.more === true, 'read_file reads a stretch and says how far there is');
  out = await tool(userWrite, 'search_files', { domain: DOMAIN, text: 'needle' });
  check(out.data?.matches?.some((m) => m.path === 'public_html/mcp-e2e/deep/note.txt' && m.line === 2), `search_files finds it, case-insensitively (${out.text.slice(0, 160)})`);
  out = await tool(userWrite, 'search_files', { domain: DOMAIN, text: 'needle', case_sensitive: true });
  check(out.data?.matches?.length === 0, 'and exactly when asked');
  out = await tool(userWrite, 'create_directory', { domain: DOMAIN, path: 'public_html/mcp-e2e/a/b' });
  check(!out.isError && out.data.created.length === 2, 'create_directory makes the folders above it');
  out = await tool(userWrite, 'move_file', { domain: DOMAIN, path: 'public_html/mcp-e2e/deep/note.txt', new_path: 'public_html/mcp-e2e/a/b/renamed.txt' });
  check(!out.isError, `move_file moves and renames at once (${out.text.slice(0, 120)})`);
  out = await tool(userWrite, 'list_files', { domain: DOMAIN, path: 'public_html/mcp-e2e/a/b' });
  check(out.data?.items?.some((i) => i.name === 'renamed.txt'), 'list_files shows it there');
  const owner = run('stat', ['-c', '%U', `${site.root_path}/public_html/mcp-e2e/a/b/renamed.txt`]).trim();
  check(owner === NAME || owner === site.linux_user, `the file belongs to the site's user (${owner})`);
  out = await tool(userWrite, 'delete_file', { domain: DOMAIN, path: 'public_html' });
  check(out.isError && /web root/.test(out.text), 'the web root is never deleted');
  out = await tool(userWrite, 'delete_file', { domain: DOMAIN, path: 'public_html/mcp-e2e' });
  check(!out.isError, 'delete_file removes a folder');
  out = await tool(userWrite, 'read_file', { domain: DOMAIN, path: 'public_html/mcp-e2e/a/b/renamed.txt' });
  check(out.isError, 'and it is gone');
  // An administrator's: a customer's package decides whether they may.
  const wafWas = (await tool(adminToken, 'get_website', { domain: DOMAIN })).data?.waf_enabled;
  out = await tool(adminToken, 'set_website_waf', { domain: DOMAIN, enabled: !wafWas });
  const wafNow = (await tool(adminToken, 'get_website', { domain: DOMAIN })).data?.waf_enabled;
  check(!out.isError && wafNow === !wafWas, `set_website_waf (${out.text.slice(0, 100)})`);
  await tool(adminToken, 'set_website_waf', { domain: DOMAIN, enabled: !!wafWas });
  out = await tool(userWrite, 'create_backup');
  check(!out.isError && out.data.job?.job_id, 'create_backup queues the account\'s backup');

  // ---------------------------------------------------------------- traffic
  out = await tool(adminToken, 'traffic_summary', { domain: DOMAIN, lines: 3000, top: 5 });
  check(out.data?.requests >= 10 && out.data.top_user_agents.some((a) => a.user_agent === 'EvilScanner/1.0' && a.requests === 4)
    && out.data.top_paths.some((p) => p.path === '/wp-login.php'), `traffic_summary adds the log up (${out.data?.requests} requests; ${JSON.stringify(out.data?.top_user_agents)})`);
  out = await tool(adminToken, 'read_waf_access_log', { domain: DOMAIN, search: 'evilscanner', limit: 2 });
  check(out.data?.requests?.length === 2 && out.data.matching === 4 && out.data.requests[0].path === '/wp-login.php', 'read_waf_access_log narrows and limits');

  // ---------------------------------------------------------------- administrators
  out = await tool(adminToken, 'list_users');
  check(out.data?.users?.some((u) => u.username === NAME) && !out.text.includes('hashed_password'), 'list_users');
  out = await tool(adminToken, 'list_services');
  check(out.data?.services?.some((s) => /nginx/.test(s.name) && s.running), `list_services (${out.text.slice(0, 120)})`);
  out = await tool(adminToken, 'panel_update_status');
  check(!out.isError, 'panel_update_status');
  out = await tool(adminToken, 'list_firewall_rules');
  check(!out.isError && Array.isArray(out.data?.rules), 'list_firewall_rules');
  for (const [ip, why] of [['10.0.0.1', 'private'], ['1.0.0.0/15', 'wider than a /16'], ['127.0.0.1', 'loopback'], ['203.0.113.7', 'documentation']]) {
    out = await tool(adminToken, 'block_ip', { ip, reason: 'e2e' });
    check(out.isError && out.text.includes(why), `block_ip refuses ${ip} (${out.text})`);
  }
  const ownIp = run('hostname', ['-I']).split(/\s+/).find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a) && !a.startsWith('127.') && !/^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(a));
  if (ownIp) {
    out = await tool(adminToken, 'block_ip', { ip: ownIp });
    check(out.isError && out.text.includes("this server's own address"), `and this server's own address (${ownIp})`);
  }
  const target = '45.33.32.156';
  out = await tool(adminToken, 'block_ip', { ip: target, reason: 'e2e scanner' });
  check(!out.isError && out.data.already === false, `block_ip blocks a public address (${out.text})`);
  out = await tool(adminToken, 'block_ip', { ip: `${target}/32` });
  check(!out.isError && out.data.already === true, 'twice is already, not a second rule');
  out = await tool(adminToken, 'unblock_ip', { ip: target });
  check(!out.isError && out.data.rules_removed >= 1, `unblock_ip removes it (${out.text})`);
  out = await tool(adminToken, 'unblock_ip', { ip: target });
  check(out.isError && /No firewall rule/.test(out.text), 'and then there is nothing to unblock');

  const siteRulesBefore = (await json(await admin.api('GET', `/waf/websites/${siteId}`))).custom_rules || '';
  out = await tool(adminToken, 'add_waf_rule', { match: 'user_agent', value: 'EvilScanner', domain: DOMAIN, note: "scanner's probe" });
  check(!out.isError && out.data.id >= 1090000 && out.data.id <= 1099999 && out.data.rule.includes('"@contains evilscanner"'), `add_waf_rule writes the rule (${out.text.slice(0, 160)})`);
  out = await tool(adminToken, 'add_waf_rule', { match: 'user_agent', value: 'bad" "id:1', domain: DOMAIN });
  check(out.isError && /quotes/.test(out.text), 'and refuses a value that could leave its quotes');
  out = await tool(adminToken, 'list_waf_rules', { domain: DOMAIN });
  check(out.data?.website?.custom_rules?.includes('snpanel-mcp: scanner s probe'), 'list_waf_rules shows it on the site');
  await admin.api('PUT', `/waf/websites/${siteId}`, { custom_rules: siteRulesBefore, enabled_rule_ids: (await json(await admin.api('GET', `/waf/websites/${siteId}`))).enabled_rule_ids });

  out = await tool(adminToken, 'restart_service', { service: 'nginx', action: 'reload' });
  check(!out.isError, `restart_service reloads nginx (${out.text.slice(0, 100)})`);
  out = await tool(adminToken, 'restart_service', { service: 'nginx', action: 'stop' });
  check(out.rpcError?.code === -32602, 'and does not stop anything');
  scheduleId = (await json(await admin.api('POST', '/maintenance/backup-schedules', { user_ids: [userId], schedule: '0 3 * * *', retention: 1 }))).id;
  out = await tool(adminToken, 'run_backup_schedule', { schedule_id: scheduleId });
  check(!out.isError, 'run_backup_schedule starts one now');
  let ran = null;
  for (let i = 0; i < 60 && !ran; i++) {
    await sleep(2000);
    const schedules = (await tool(adminToken, 'list_backup_schedules')).data?.schedules || [];
    ran = schedules.find((s) => s.id === scheduleId && s.last_run_at);
  }
  check(ran?.last_status === 'ok', `and list_backup_schedules shows how it went (${ran?.last_status}: ${ran?.last_message})`);
  out = await tool(adminToken, 'list_backups', { username: NAME });
  check(out.data?.backups?.length >= 1, 'list_backups names another account for an administrator');

  // ---------------------------------------------------------------- the audit log
  out = await tool(adminToken, 'recent_audit_log', { limit: 100 });
  const entries = JSON.stringify(out.data);
  check(entries.includes('mcp_tool') && entries.includes('write_file') && entries.includes('<') && !entries.includes('Needle in the second line'),
    'every action is audited as mcp_tool, a file only by its length');

  // ---------------------------------------------------------------- a token's life
  const expiring = await make(user, 'e2e expiring', false);
  sql("update mcp_tokens set expires_at = '2020-01-01 00:00:00.000000' where name = ?", 'e2e expiring');
  r = await rpc(expiring, { jsonrpc: '2.0', id: 1, method: 'ping' });
  check(r.status === 401 && /expired/.test(r.text), 'an expired token: 401');
  await admin.api('POST', `/users/${userId}/suspend`);
  r = await rpc(userRead, { jsonrpc: '2.0', id: 1, method: 'ping' });
  check(r.status === 401 && /suspended/.test(r.text), "a suspended account's token: 401");
  await admin.api('POST', `/users/${userId}/unsuspend`);
  r = await rpc(userRead, { jsonrpc: '2.0', id: 1, method: 'ping' });
  check(r.status === 200, 'and it works again once the account does');

  // The Addons page: every token, and one revoked from there.
  await page.goto(`${BASE}/addons`, { waitUntil: 'networkidle' });
  const panel = page.locator('.mcp-panel');
  await panel.waitFor();
  check((await panel.innerText()).includes(`${NAME} · e2e user read`), "the Addons page lists every account's tokens");
  await page.screenshot({ path: `${OUT}/addons-light-en.png`, fullPage: true });
  await panel.locator('.backup-item', { hasText: 'e2e user read' }).getByRole('button').click();
  await page.getByText('Token e2e user read revoked.').waitFor();
  r = await rpc(userRead, { jsonrpc: '2.0', id: 1, method: 'ping' });
  check(r.status === 401, 'a revoked token: 401 at once');

  // Off, on.
  await admin.api('POST', '/addons/mcp/uninstall');
  r = await rpc(adminToken, { jsonrpc: '2.0', id: 1, method: 'ping' });
  check(r.status === 404 && /not enabled/.test(r.text), 'with the addon uninstalled: 404');
  const kept = (await json(await admin.api('GET', '/mcp/tokens'))).items || [];
  check(kept.some((t) => t.name === 'e2e admin'), 'and the tokens are kept');
  await admin.api('POST', '/addons/mcp/install');
  r = await rpc(adminToken, { jsonrpc: '2.0', id: 1, method: 'ping' });
  check(r.status === 200, 'installed again, they work again');

  // ---------------------------------------------------------------- the pages
  await page.goto(`${BASE}/dashboard`, { waitUntil: 'networkidle' });
  check(await page.getByRole('link', { name: /AI assistants \(MCP\)/ }).count() >= 1, 'the addon has its tile on the Dashboard');
  for (const [theme, locale] of [['dark', 'en'], ['light', 'vi']]) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
    await context.addInitScript(([t, l]) => { try { localStorage.setItem('snpanel-theme', t); localStorage.setItem('snpanel-locale', l); } catch {} }, [theme, locale]);
    await logIn(context);
    const shot = await context.newPage();
    await shot.goto(`${BASE}/ai-assistants`, { waitUntil: 'networkidle' });
    await shot.waitForTimeout(400);
    await shot.screenshot({ path: `${OUT}/page-${theme}-${locale}.png`, fullPage: true });
    await context.close();
  }
  // A session of its own: the suspension above ended the user's.
  const phoneUser = await session(NAME, PASSWORD);
  const phone = await phoneUser.context.newPage();
  await phone.setViewportSize({ width: 390, height: 844 });
  await phone.goto(`${BASE}/ai-assistants`, { waitUntil: 'networkidle' });
  await phone.waitForTimeout(400);
  const wide = await phone.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  const heading = await phone.getByRole('heading', { level: 2, name: 'AI assistants (MCP)' }).count();
  check(heading === 1 && wide <= 0, `a user sees the page on a phone without sideways scroll (${wide}px)`);
  await phone.screenshot({ path: `${OUT}/page-phone-user.png`, fullPage: true });
  check(consoleErrors.length === 0, `no console errors (${consoleErrors.slice(0, 3).join(' | ')})`);
} finally {
  if (scheduleId) await admin.api('DELETE', `/maintenance/backup-schedules/${scheduleId}`);
  for (const id of tokens) await admin.api('DELETE', `/mcp/tokens/${id}`);
  const mine = (await json(await admin.api('GET', '/mcp/tokens'))).items || [];
  for (const t of mine.filter((t) => t.name.startsWith('e2e'))) await admin.api('DELETE', `/mcp/tokens/${t.id}`);
  if (siteId) await admin.api('DELETE', `/websites/${siteId}?delete_files=true`);
  if (userId) await admin.api('DELETE', `/users/${userId}`);
  run('rm', ['-rf', `/var/backups/snpanel/users/${NAME}`]);
  if (!wasInstalled) await admin.api('POST', '/addons/mcp/uninstall');
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
