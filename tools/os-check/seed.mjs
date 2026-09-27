// seed.mjs - data to look at the pages with, on a test machine: sites,
// databases, files, cron, a backup and a schedule, a customer with SFTP and a
// site of their own, firewall rules, Fail2ban, WAF on one site, and two
// malware scans - one clean, one that finds the EICAR test file.
//
// Runs on the machine, as root, like smoke.mjs; skips what already exists.
// The customer's generated password goes to /root/demo-login.txt (0600).
import https from 'node:https';
import { readFileSync, writeFileSync, chmodSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const BASE = 'https://127.0.0.1:2222';
const login = readFileSync('/root/login.txt', 'utf8');
const ADMIN = /^User: (.+)$/m.exec(login)?.[1]?.trim() || 'admin';
const PASSWORD = /^Password: (.+)$/m.exec(login)?.[1]?.trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function session() {
  const jar = new Map();
  return async function api(method, path, body, { form } = {}) {
    const headers = {};
    let payload;
    if (form) { headers['Content-Type'] = 'application/x-www-form-urlencoded'; payload = new URLSearchParams(form).toString(); }
    else if (body !== undefined || !['GET', 'HEAD'].includes(method)) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body ?? {}); }
    if (payload !== undefined) headers['Content-Length'] = Buffer.byteLength(payload);
    headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    if (!['GET', 'HEAD'].includes(method) && jar.get('snpanel_csrf')) headers['X-CSRF-Token'] = jar.get('snpanel_csrf');
    const url = new URL(`${BASE}/api${path}`);
    return new Promise((resolve, reject) => {
      const req = https.request(url, { method, headers, rejectUnauthorized: false }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          for (const c of res.headers['set-cookie'] || []) {
            const [pair] = c.split(';');
            const i = pair.indexOf('=');
            jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
          }
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(text); } catch {}
          resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, json, text });
        });
      });
      req.setTimeout(1800000, () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  };
}
const say = (what, r) => console.log(`${r.ok ? 'ok  ' : 'FAIL'} ${what} (${r.status})${r.ok ? '' : ` ${(r.text || '').slice(0, 200)}`}`);
const list = (r) => (Array.isArray(r.json) ? r.json : r.json?.items || r.json?.websites || r.json?.databases || []);

const admin = session();
say('admin signs in', await admin('POST', '/auth/login', undefined, { form: { username: ADMIN, password: PASSWORD } }));

// --- sites --------------------------------------------------------------------
const wantSites = [
  { domain: 'shop.example.com', app_type: 'php', php_version: '8.4' },
  { domain: 'blog.example.com', app_type: 'php', php_version: '8.3' },
  { domain: 'landing.example.com', app_type: 'static' },
];
let sites = list(await admin('GET', '/websites'));
for (const want of wantSites) {
  if (sites.some((s) => s.domain === want.domain)) continue;
  say(`site ${want.domain}`, await admin('POST', '/websites', want));
}
sites = list(await admin('GET', '/websites'));
const byDomain = (d) => sites.find((s) => s.domain === d);
const shop = byDomain('shop.example.com');
const blog = byDomain('blog.example.com');

// --- databases ------------------------------------------------------------------
const dbs = list(await admin('GET', '/databases'));
for (const [name, site] of [['shop_db', shop], ['blog_db', blog]]) {
  if (!site || dbs.some((d) => d.db_name === name)) continue;
  say(`database ${name}`, await admin('POST', '/databases', { db_name: name, website_id: site.id }));
}

// --- files and cron -------------------------------------------------------------
if (shop) {
  for (const [path, content] of [
    ['public_html/index.php', '<?php echo "Shop";\n'],
    ['public_html/config.php', '<?php return ["debug" => false];\n'],
    ['public_html/robots.txt', 'User-agent: *\nDisallow:\n'],
  ]) say(`file ${path}`, await admin('POST', '/maintenance/files/write', { website_id: shop.id, path, content }));
  const cron = list(await admin('GET', '/maintenance/cron'));
  if (!cron.length) {
    say('cron 1', await admin('POST', '/maintenance/cron', { website_id: shop.id, schedule: '*/15 * * * *', command: 'php -q cron.php' }));
    say('cron 2', await admin('POST', '/maintenance/cron', { website_id: shop.id, schedule: '0 3 * * *', command: 'php -q cleanup.php' }));
  }
}

// --- backups --------------------------------------------------------------------
if (shop) say('backup now', await admin('POST', '/maintenance/backup', { website_id: shop.id }));
const schedules = list(await admin('GET', '/maintenance/backup-schedules'));
if (!schedules.length) {
  say('backup schedule', await admin('POST', '/maintenance/backup-schedules', { all_users: true, schedule: '0 3 * * *', retention: 7, name_style: 'weekday', is_active: true }));
}

// --- a customer, their SFTP login and a site of their own -------------------------
let users = list(await admin('GET', '/users'));
let demo = users.find((u) => u.username === 'demo');
if (!demo) {
  const password = `Demo-${randomBytes(12).toString('base64url')}`;
  const r = await admin('POST', '/users', { username: 'demo', email: 'demo@example.com', password, role: 'end_user', website_limit: 3, storage_limit_mb: 1000 });
  say('customer demo', r);
  if (r.ok) {
    writeFileSync('/root/demo-login.txt', `Panel\nUser: demo\nPassword: ${password}\n`);
    chmodSync('/root/demo-login.txt', 0o600);
    demo = r.json;
  }
}
if (demo?.id) say('demo SFTP on', await admin('PUT', `/users/${demo.id}/sftp`, { enabled: true, generate: true }));
if (existsSync('/root/demo-login.txt')) {
  const dl = readFileSync('/root/demo-login.txt', 'utf8');
  const customer = session();
  say('demo signs in', await customer('POST', '/auth/login', undefined, { form: { username: 'demo', password: /^Password: (.+)$/m.exec(dl)[1].trim() } }));
  const theirs = list(await customer('GET', '/websites'));
  if (!theirs.some((s) => s.domain === 'demo-store.example.com')) {
    say('demo site', await customer('POST', '/websites', { domain: 'demo-store.example.com', app_type: 'php', php_version: '8.4' }));
  }
  const site = list(await customer('GET', '/websites')).find((s) => s.domain === 'demo-store.example.com');
  const theirDbs = list(await customer('GET', '/databases'));
  if (site && !theirDbs.length) say('demo database', await customer('POST', '/databases', { db_name: 'store_db', website_id: site.id }));
}

// --- firewall, Fail2ban, WAF ------------------------------------------------------
say('firewall allow 8081', await admin('POST', '/firewall/allow-port', { port: '8081', protocol: 'tcp' }));
say('firewall block 203.0.113.50', await admin('POST', '/firewall/block-ip', { ip: '203.0.113.50', port: null, protocol: 'tcp' }));
say('Fail2ban installed', await admin('POST', '/addons/fail2ban/install', {}));
if (shop) say('WAF on shop', await admin('PATCH', `/websites/${shop.id}/waf`, { waf_enabled: true }));

// --- malware: one clean scan, one that finds the EICAR file ----------------------
say('scanner on', await admin('POST', '/malware/toggle', { enabled: true }));
for (let i = 0; i < 60; i += 1) {
  const st = await admin('GET', '/malware/status');
  if (st.json?.lmd_installed) break;
  await sleep(5000);
}
if (blog?.root_path) {
  const file = `${blog.root_path}/public_html/eicar.com.txt`;
  writeFileSync(file, 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
  spawnSync('chown', ['--reference', `${blog.root_path}/public_html`, file]);
}
for (const site of [shop, blog].filter(Boolean)) {
  const run = await admin('POST', '/malware/run', { website_id: site.id });
  say(`scan ${site.domain}`, run);
  const id = run.json?.job_id;
  for (let i = 0; id && i < 120; i += 1) {
    const j = await admin('GET', `/malware/jobs/${id}`);
    if (['done', 'infected', 'error', 'interrupted'].includes(j.json?.status)) {
      console.log(`     ${site.domain}: ${j.json.status}, ${j.json.scanned ?? '?'} files, ${(j.json.threats || []).length} threats`);
      break;
    }
    await sleep(3000);
  }
}
console.log('seeded');
