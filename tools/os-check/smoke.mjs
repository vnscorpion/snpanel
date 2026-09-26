// smoke.mjs - the panel's features on this machine, through its own API and
// checked against the machine itself. Run as root on an installed box:
//
//     node smoke.mjs                 # everything but the heavy parts
//     SMOKE_CLAMAV=1 SMOKE_MALDET=1 SMOKE_DOCKER=1 node smoke.mjs
//
// It asks the machine rather than assuming a distribution, so the same script
// runs on Ubuntu, Debian and AlmaLinux and a difference between them shows up
// as a FAIL on one and a PASS on the others. Everything it makes - sites,
// databases, a user, rules, addons - it removes again.
import { spawnSync } from 'node:child_process';
import https from 'node:https';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const BASE = process.env.PANEL_BASE || 'https://127.0.0.1:2222';
const login = readFileSync('/root/login.txt', 'utf8');
const ADMIN = /^User: (.+)$/m.exec(login)?.[1]?.trim() || 'admin';
const PASSWORD = /^Password: (.+)$/m.exec(login)?.[1]?.trim();
const TAG = randomBytes(3).toString('hex');
const results = [];
let section = '';

const out = (line) => process.stdout.write(`${line}\n`);
const check = (cond, what, why = '') => {
  results.push({ section, ok: !!cond, what });
  out(`  ${cond ? 'PASS' : 'FAIL'}  ${what}${!cond && why ? `  -- ${String(why).slice(0, 300)}` : ''}`);
  return !!cond;
};
const skip = (what, why) => { results.push({ section, skip: true, what }); out(`  SKIP  ${what}  -- ${why}`); };
const begin = (name) => { section = name; out(`\n=== ${name} ===`); };
const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: opts.timeout || 120000, env: { ...process.env, ...(opts.env || {}) }, input: opts.input });
  return { ok: r.status === 0, code: r.status, out: `${r.stdout || ''}${r.stderr || ''}`.trim() };
};
const sh = (script, opts) => run('/bin/sh', ['-c', script], opts);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const secret = () => `Sm0ke-${randomBytes(12).toString('base64url')}`;
const osRelease = readFileSync('/etc/os-release', 'utf8');
const IS_EL = /^ID_LIKE=.*(rhel|fedora)/m.test(osRelease) || /^ID="?(almalinux|rocky|rhel|centos)/m.test(osRelease);

// --- the session -------------------------------------------------------------
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
const remember = (setCookies) => {
  for (const c of setCookies || []) {
    const [pair] = c.split(';');
    const i = pair.indexOf('=');
    jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
};
// node:https rather than fetch: fetch gives up on a response whose headers
// take more than 300 s, and installing a PHP version from the panel can.
async function api(method, path, body, { form, multipart, bearer, timeout = 1800000 } = {}) {
  const headers = {};
  let payload;
  if (multipart) {
    // Let the platform encode the form, then send its bytes.
    const encoded = new Response(multipart);
    headers['Content-Type'] = encoded.headers.get('content-type');
    payload = Buffer.from(await encoded.arrayBuffer());
  } else if (form) { headers['Content-Type'] = 'application/x-www-form-urlencoded'; payload = new URLSearchParams(form).toString(); }
  else if (body !== undefined || !['GET', 'HEAD'].includes(method)) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body ?? {}); }
  if (payload !== undefined) headers['Content-Length'] = Buffer.byteLength(payload);
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  else {
    headers.Cookie = cookieHeader();
    if (!['GET', 'HEAD'].includes(method) && jar.get('snpanel_csrf')) headers['X-CSRF-Token'] = jar.get('snpanel_csrf');
  }
  const url = new URL(`${BASE}${path.startsWith('/api') ? path : `/api${path}`}`);
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers, rejectUnauthorized: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        remember(res.headers['set-cookie']);
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch {}
        resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, json, text });
      });
    });
    req.setTimeout(timeout, () => req.destroy(new Error(`no answer in ${timeout / 1000} s`)));
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}
const detail = (r) => r.json?.detail ? JSON.stringify(r.json.detail) : r.text.slice(0, 200);
async function poll(path, done, { every = 2000, limit = 900000 } = {}) {
  const until = Date.now() + limit;
  let last;
  while (Date.now() < until) {
    last = await api('GET', path);
    if (last.json && done(last.json)) return last.json;
    await sleep(every);
  }
  return last?.json;
}
// A request to a site through nginx on this machine.
const web = (host, path = '/', { https = false, extra = [] } = {}) => {
  const port = https ? 443 : 80;
  sh('rm -f /tmp/smoke-body');
  const r = run('curl', ['-sk', '--max-time', '60', '-o', '/tmp/smoke-body', '-w', '%{http_code} %{redirect_url}', '--resolve', `${host}:${port}:127.0.0.1`, ...extra, `${https ? 'https' : 'http'}://${host}${path}`]);
  const body = existsSync('/tmp/smoke-body') ? readFileSync('/tmp/smoke-body', 'utf8') : '';
  const [code, location = ''] = r.out.trim().split(' ');
  return { code: Number(code) || 0, body, location };
};
async function webUntil(host, path, want, opts = {}) {
  let r = web(host, path, opts);
  for (let i = 0; i < (opts.seconds || 15) && !want(r); i += 1) {
    await sleep(1000);
    r = web(host, path, opts);
  }
  return r;
}
const writeFile = (id, path, content) => api('POST', '/maintenance/files/write', { website_id: id, path, content });
const made = { sites: [], dbs: [], users: [], rules: [] };
let siteHttps = false;

async function main() {
  out(`SNPanel smoke test on ${/^PRETTY_NAME="?([^"\n]+)/m.exec(osRelease)?.[1]} (${IS_EL ? 'EL' : 'Debian family'}), tag ${TAG}`);

  begin('panel');
  const health = await api('GET', '/health');
  check(health.ok, `/api/health answers (${health.json?.version || health.status})`, detail(health));
  const li = await api('POST', '/auth/login', undefined, { form: { username: ADMIN, password: PASSWORD } });
  if (!check(li.ok && jar.get('snpanel_session'), `the administrator signs in (${li.status})`, detail(li))) return;
  const session = await api('GET', '/auth/session');
  check(session.json?.authenticated && session.json?.user?.role === 'admin', 'the session is an administrator');

  begin('services');
  const services = (await api('GET', '/services/list')).json?.services || [];
  check(services.length >= 4, `the Services page lists ${services.length}: ${services.join(' ')}`);
  for (const name of services) {
    const r = await api('POST', '/services/action', { name, action: 'status' });
    check(r.json?.returncode === 0, `${name} is running`, r.json?.stdout || detail(r));
  }
  const usage = (await api('GET', '/services/resource-usage')).json;
  check(usage?.cpu && usage?.memory?.total > 0 && usage?.disk?.total > 0, `the Dashboard's figures (cpu ${usage?.cpu?.percent}%, memory ${usage?.memory?.percent}%)`);

  begin('PHP versions');
  const versions = (await api('GET', '/maintenance/php-versions')).json || {};
  const installed = versions.installed || [];
  check(installed.length >= 2, `installed: ${installed.join(' ')}; offered: ${(versions.supported || []).join(' ')}`);
  const newest = installed[installed.length - 1];
  const older = installed[0];

  begin('websites');
  const staticDomain = `st-${TAG}.example.com`;
  const phpDomain = `php-${TAG}.example.com`;
  const st = await api('POST', '/websites', { domain: staticDomain, app_type: 'static' });
  check(st.ok && st.json?.id, `a static site (${st.status})`, detail(st));
  if (st.json?.id) {
    made.sites.push(st.json);
    const page = await webUntil(staticDomain, '/', (r) => r.code === 200);
    check(page.code === 200, `nginx serves it (${page.code})`);
  }
  const site = await api('POST', '/websites', { domain: phpDomain, app_type: 'php', php_version: newest });
  const s = site.json;
  check(site.ok && s?.id, `a PHP ${newest} site owned by ${s?.linux_user} at ${s?.root_path}`, detail(site));
  if (!s?.id) return;
  made.sites.push(s);
  const probe = '<?php header("Content-Type: text/plain"); echo "php-ok-", PHP_VERSION, " ", ini_get("memory_limit"), " opcache=", (int) ini_get("opcache.enable"), " user=", get_current_user();';
  let w = await writeFile(s.id, 'public_html/probe.php', probe);
  check(w.ok, 'the file manager writes a PHP file', detail(w));
  let p = await webUntil(phpDomain, '/probe.php', (r) => r.body.startsWith(`php-ok-${newest}`));
  check(p.code === 200 && p.body.startsWith(`php-ok-${newest}`), `PHP ${newest} runs through nginx: ${p.body.slice(0, 60)}`, `${p.code} ${p.body.slice(0, 200)}`);
  if (older && older !== newest) {
    const sw = await api('PATCH', `/websites/${s.id}`, { php_version: older });
    p = await webUntil(phpDomain, '/probe.php', (r) => r.body.startsWith(`php-ok-${older}`));
    check(sw.ok && p.body.startsWith(`php-ok-${older}`), `switched to PHP ${older}: ${p.body.slice(0, 40)}`, `${detail(sw)} ${p.body.slice(0, 120)}`);
    await api('PATCH', `/websites/${s.id}`, { php_version: newest });
    await webUntil(phpDomain, '/probe.php', (r) => r.body.startsWith(`php-ok-${newest}`));
  }
  const logs = await api('GET', `/websites/${s.id}/logs?kind=access&lines=50`);
  check(logs.json?.content?.includes('/probe.php'), `the log viewer shows the request (${logs.json?.path})`, detail(logs));
  const alias = await api('POST', `/websites/${s.id}/aliases`, { domain: `alias-${TAG}.example.com`, mode: 'alias' });
  const ap = await webUntil(`alias-${TAG}.example.com`, '/probe.php', (r) => r.body.startsWith('php-ok-'));
  check(alias.ok && ap.body.startsWith('php-ok-'), `an alias serves the same site (${ap.code})`, detail(alias));

  // A certificate of our own, uploaded the way the SSL page does it.
  const cert = sh(`openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=${phpDomain} -addext subjectAltName=DNS:${phpDomain},DNS:alias-${TAG}.example.com -keyout /tmp/smoke.key -out /tmp/smoke.crt 2>&1`);
  if (check(cert.ok, 'openssl makes a certificate', cert.out)) {
    const fd = new FormData();
    fd.set('certificate_text', readFileSync('/tmp/smoke.crt', 'utf8'));
    fd.set('private_key_text', readFileSync('/tmp/smoke.key', 'utf8'));
    const ssl = await api('POST', `/websites/${s.id}/ssl/manual`, undefined, { multipart: fd });
    const tls = await webUntil(phpDomain, '/probe.php', (r) => r.code === 200, { https: true });
    check(ssl.ok && tls.code === 200 && tls.body.startsWith('php-ok-'), `a custom certificate is served over HTTPS (${ssl.status}, ${tls.code})`, detail(ssl));
    if (ssl.ok) siteHttps = true;
  }
  const flood = await api('PATCH', `/websites/${s.id}/http-flood`, { http_flood_enabled: true });
  const nginxT = run('nginx', ['-t']);
  check(flood.ok && nginxT.ok, 'HTTP flood limits on, and nginx -t still passes', `${detail(flood)} ${nginxT.out.slice(-200)}`);
  await api('PATCH', `/websites/${s.id}/http-flood`, { http_flood_enabled: false });

  begin('WAF');
  const waf = await api('GET', '/waf/status');
  let wafState = {};
  try { wafState = JSON.parse(waf.json?.stdout || '{}'); } catch { wafState = { installed: (waf.json?.stdout || '').trim() === 'installed' }; }
  if (!wafState.installed) {
    skip('ModSecurity', `the engine is not installed here (${(waf.json?.stdout || waf.text).replace(/\s+/g, ' ').slice(0, 120)})`);
  } else {
    const rules = (await api('GET', '/waf/rules')).json;
    const ids = (rules?.default_rule_definitions || []).map((r) => r.id);
    const modeBefore = (await api('GET', '/waf/crs')).json?.mode;
    // One switch: WAF on is the panel's rules and the OWASP rule set blocking.
    const on = await api('PATCH', `/websites/${s.id}/waf`, { waf_enabled: true });
    const put = await api('PUT', `/waf/websites/${s.id}`, { enabled_rule_ids: ids, custom_rules: '' });
    await webUntil(phpDomain, '/.git/config', (r) => r.code === 403, { seconds: 10, https: siteHttps });
    const blocked = ['/.git/config', '/.env', '/composer.lock', '/wp-config.php.bak'].map((path) => [path, web(phpDomain, path, { https: siteHttps }).code]);
    check(on.ok && put.ok && blocked.some(([, code]) => code === 403), `the default rules block probes: ${blocked.map(([a, b]) => `${a} ${b}`).join(', ')}`, `${detail(on)} ${detail(put)}`);
    // Real requests, not only nginx -t: an include that loads CRS without its
    // setup file passes nginx -t and answers every request with a 500.
    check(web(phpDomain, '/probe.php', { https: siteHttps }).code === 200, 'and let the site through');
    const cfg = (await api('GET', `/waf/websites/${s.id}`)).json;
    const attack = '/probe.php?id=1%27%20OR%20%271%27%3D%271';
    const refused = await webUntil(phpDomain, attack, (r) => r.code === 403, { seconds: 10, https: siteHttps });
    check(cfg?.crs_active && refused.code === 403, `the same switch turns the OWASP rule set on, blocking: an SQL injection is refused (${refused.code})`, JSON.stringify(cfg || {}).slice(0, 200));
    const off = await api('PATCH', `/websites/${s.id}/waf`, { waf_enabled: false });
    const cfgOff = (await api('GET', `/waf/websites/${s.id}`)).json;
    const through = await webUntil(phpDomain, attack, (r) => r.code === 200, { seconds: 10, https: siteHttps });
    check(off.ok && !cfgOff?.crs_enabled && through.code === 200, `and off takes both off (${through.code})`, detail(off));
    if (modeBefore && modeBefore !== 'block') await api('PUT', '/waf/crs', { mode: modeBefore });
  }
  const access = await api('GET', `/waf/access-logs?website_id=${s.id}&limit=20`);
  check(access.ok && access.json?.total > 0, `Access Logs reads the site's log (${access.json?.total} lines)`, detail(access));

  begin('PHP settings');
  for (const v of installed) {
    const cfg = await api('GET', `/maintenance/php-config?php_version=${v}`);
    const set = await api('POST', '/maintenance/php-config', { ...cfg.json, php_version: v, memory_limit: '384M' });
    check(cfg.ok && set.ok, `PHP ${v}: settings read and written (${set.json?.target || detail(set)})`);
  }
  p = await webUntil(phpDomain, '/probe.php', (r) => r.body.includes(' 384M '), { https: siteHttps });
  check(p.body.includes(' 384M '), `the new memory_limit reaches PHP-FPM: ${p.body.slice(0, 60)}`, p.body.slice(0, 120));
  const opcOff = await api('POST', '/maintenance/php-opcache', { php_version: newest, enabled: false });
  p = await webUntil(phpDomain, '/probe.php', (r) => r.body.includes('opcache=0'), { https: siteHttps });
  check(opcOff.ok && p.body.includes('opcache=0'), `OPcache off for PHP ${newest}: ${p.body.slice(0, 60)}`, detail(opcOff));
  await api('POST', '/maintenance/php-opcache', { php_version: newest, enabled: true });
  const term = await api('POST', `/terminal/exec/${s.id}`, { command: 'php -v' });
  check(term.json?.exit_code === 0 && /PHP \d/.test(term.json?.stdout || ''), `the terminal runs the site's PHP: ${(term.json?.stdout || '').split('\n')[0]}`, detail(term));
  const want = ['8.2', '8.3', '8.4', '8.5'].find((v) => !installed.includes(v) && (versions.supported || []).includes(v));
  if (want) {
    const inst = await api('POST', `/maintenance/php-versions/${want}/install`, {});
    const after = (await api('GET', '/maintenance/php-versions')).json?.installed || [];
    const ok = check(inst.ok && after.includes(want), `installing PHP ${want} from the panel (${inst.status})`, detail(inst));
    if (ok) {
      await api('PATCH', `/websites/${s.id}`, { php_version: want });
      p = await webUntil(phpDomain, '/probe.php', (r) => r.body.startsWith(`php-ok-${want}`), { https: siteHttps });
      check(p.body.startsWith(`php-ok-${want}`), `a site runs on the new PHP ${want}: ${p.body.slice(0, 30)}`, p.body.slice(0, 120));
      await api('PATCH', `/websites/${s.id}`, { php_version: newest });
      await webUntil(phpDomain, '/probe.php', (r) => r.body.startsWith(`php-ok-${newest}`), { https: siteHttps });
    }
  } else skip('installing another PHP version', 'every supported version is installed already');

  begin('databases');
  const db = await api('POST', '/databases', { db_name: `smk_${TAG}`, website_id: s.id });
  if (check(db.ok && db.json?.db_password, `a database for the site (${db.json?.db_name})`, detail(db))) {
    made.dbs.push(db.json);
    const q = run('mariadb', ['-u', db.json.db_user, db.json.db_name, '-N', '-e', 'SELECT 40+2'], { env: { MYSQL_PWD: db.json.db_password } });
    check(q.ok && q.out.includes('42'), 'its user signs in to MariaDB with the password the panel gave', q.out);
    const sso = await api('POST', `/databases/${db.json.id}/phpmyadmin-sso`, {});
    const url = sso.json?.url ? new URL(sso.json.url) : null;
    if (check(url, `phpMyAdmin single sign-on link (${url?.origin})`, detail(sso))) {
      const port = url.port || (url.protocol === 'https:' ? 443 : 80);
      const pma = run('curl', ['-sk', '-L', '--max-time', '60', '-c', '/tmp/smoke-pma', '-b', '/tmp/smoke-pma', '--resolve', `${url.hostname}:${port}:127.0.0.1`, '-o', '/tmp/smoke-pma.html', '-w', '%{http_code}', url.href]);
      const html = existsSync('/tmp/smoke-pma.html') ? readFileSync('/tmp/smoke-pma.html', 'utf8') : '';
      check(pma.out.endsWith('200') && /phpMyAdmin/.test(html) && html.includes(db.json.db_name), `phpMyAdmin opens signed in, on the database (${pma.out.slice(-3)})`, html.replace(/\s+/g, ' ').slice(0, 200));
    }
  }

  begin('files');
  const F = (path, body) => api('POST', `/maintenance/files/${path}`, { website_id: s.id, ...body });
  const mk = await F('mkdir', { path: 'public_html', name: 'smkdir' });
  const cr = await F('create', { path: 'public_html', name: 'a.txt' });
  const wr = await writeFile(s.id, 'public_html/a.txt', 'hello from the smoke test');
  const rd = await api('GET', `/maintenance/files/${s.id}/read?path=public_html/a.txt`);
  check(mk.ok && cr.ok && wr.ok && rd.json?.content === 'hello from the smoke test', 'mkdir, create, write and read', `${detail(mk)} ${detail(cr)} ${detail(rd)}`);
  const rn = await F('rename', { path: 'public_html/a.txt', new_name: 'b.txt' });
  const cm = await F('chmod', { path: 'public_html/b.txt', mode: '640' });
  const ls = await api('GET', `/maintenance/files/${s.id}?path=public_html`);
  const b = (ls.json?.items || []).find((i) => i.name === 'b.txt');
  check(rn.ok && cm.ok && b?.mode === '640', `rename and chmod (b.txt ${b?.mode})`, `${detail(rn)} ${detail(cm)}`);
  const onDisk = sh(`stat -c '%U %a' '${s.root_path}/public_html/b.txt'`);
  check(onDisk.out === `${s.linux_user} 640`, `on disk it is the site user's: ${onDisk.out}`);
  const zip = await F('archive', { base_path: 'public_html', paths: ['public_html/b.txt'], output_name: `smk-${TAG}.zip`, format: 'zip' });
  const ex = await F('extract', { archive_path: `public_html/smk-${TAG}.zip`, destination_path: 'public_html/smkdir' });
  const job = ex.json?.job_id ? await poll(`/maintenance/files/jobs/${ex.json.job_id}`, (j) => ['done', 'error'].includes(j.status), { every: 1500, limit: 120000 }) : null;
  const inDir = await api('GET', `/maintenance/files/${s.id}?path=public_html/smkdir`);
  check(zip.ok && job?.status === 'done' && (inDir.json?.items || []).some((i) => i.name === 'b.txt'), `zip, then extract as a job (${job?.status})`, `${detail(zip)} ${detail(ex)} ${job?.error || ''}`);
  const up = new FormData();
  up.set('file', new Blob(['uploaded body\n']), 'up.txt');
  const upl = await api('POST', `/maintenance/files/${s.id}/upload?path=public_html`, undefined, { multipart: up });
  check(upl.ok && (await webUntil(phpDomain, '/up.txt', (r) => r.code === 200, { https: siteHttps })).body === 'uploaded body\n', `an upload lands and is served (${upl.status})`, detail(upl));
  const del = await F('delete', { paths: ['public_html/smkdir', 'public_html/b.txt', 'public_html/up.txt', `public_html/smk-${TAG}.zip`] });
  check(del.ok, 'and delete', detail(del));

  begin('cron');
  const cronAdd = await api('POST', '/maintenance/cron', { website_id: s.id, schedule: '*/15 * * * *', command: 'php -q probe.php' });
  const crontab = run('crontab', ['-l', '-u', s.linux_user]);
  check(cronAdd.ok && crontab.out.includes('probe.php'), `a cron job lands in ${s.linux_user}'s crontab`, `${detail(cronAdd)} ${crontab.out.slice(0, 200)}`);
  const cronList = (await api('GET', `/maintenance/cron/${s.id}`)).json;
  const item = (cronList?.items || []).find((i) => i.command?.includes('probe.php') || i.line?.includes('probe.php'));
  const binary = cronList?.php_binary;
  check(binary && run(binary, ['-v']).ok, `and it runs the site's PHP binary, which exists: ${binary}`);
  if (item) {
    const cd = await api('DELETE', '/maintenance/cron', { website_id: s.id, index: item.index });
    check(cd.ok && !run('crontab', ['-l', '-u', s.linux_user]).out.includes('probe.php'), 'and is removed', detail(cd));
  }

  begin('backups');
  const bk = await api('POST', '/maintenance/backup', { website_id: s.id });
  const bj = bk.json?.job_id ? await poll(`/maintenance/backup-jobs/${bk.json.job_id}`, (j) => ['done', 'error'].includes(j.status)) : null;
  check(bj?.status === 'done', `a site backup (${bj?.status}: ${bj?.backup_file || bj?.error || detail(bk)})`);
  const items = (await api('GET', `/maintenance/backups/${s.id}`)).json?.items || [];
  if (items.length) {
    await writeFile(s.id, 'public_html/probe.php', '<?php echo "changed";');
    const rs = await api('POST', '/maintenance/restore', { website_id: s.id, backup_file: items[0] });
    p = await webUntil(phpDomain, '/probe.php', (r) => r.body.startsWith('php-ok-'), { https: siteHttps });
    check(rs.ok && p.body.startsWith('php-ok-'), `restoring it brings the file back (${rs.status})`, `${detail(rs)} ${p.body.slice(0, 80)}`);
    const bd = await api('DELETE', `/maintenance/backups/${s.id}?backup_file=${encodeURIComponent(items[0])}`);
    check(bd.ok, 'and the archive is deleted', detail(bd));
  }

  begin('users and SFTP');
  const uname = `smk${TAG}`;
  const user = await api('POST', '/users', { username: uname, email: `${uname}@example.com`, password: secret(), role: 'end_user', website_limit: 2, storage_limit_mb: 500 });
  if (check(user.ok && user.json?.id, `an end user ${uname}`, detail(user))) {
    made.users.push(user.json);
    check(run('id', [uname]).ok, `with a Linux account: ${run('id', [uname]).out}`);
    const ub = await api('POST', '/maintenance/user-backup', { user_id: user.json.id });
    const ubj = ub.json?.job_id ? await poll(`/maintenance/backup-jobs/${ub.json.job_id}`, (j) => ['done', 'error'].includes(j.status)) : null;
    check(ubj?.status === 'done', `a full user backup (${ubj?.status}: ${ubj?.backup_file || ubj?.error || detail(ub)})`);
    const on = await api('PUT', `/users/${user.json.id}/sftp`, { enabled: true, generate: true });
    const port = on.json?.ports?.[0] || 22;
    if (check(on.ok && on.json?.password, `SFTP switched on, port ${port}`, detail(on))) {
      const haveSshpass = run('sh', ['-c', 'command -v sshpass']).ok;
      if (!haveSshpass) sh(IS_EL ? 'dnf -y -q install sshpass' : 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sshpass', { timeout: 300000 });
      // Not `-b`: batch mode turns password authentication off.
      const sftp = (pw) => run('sshpass', ['-e', 'sftp', '-P', String(port), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'PubkeyAuthentication=no', `${uname}@127.0.0.1`], { env: { SSHPASS: pw }, input: 'pwd\nls\nbye\n', timeout: 60000 });
      const inside = sftp(on.json.password);
      check(/Remote working directory: \//.test(inside.out), `the user signs in over SFTP, chrooted to their home (${(/Remote working directory: \S+/.exec(inside.out) || [''])[0]})`, inside.out.slice(-300));
      const off = await api('PUT', `/users/${user.json.id}/sftp`, { enabled: false });
      check(off.ok && !/Remote working directory/.test(sftp(on.json.password).out), 'switched off, the same password is refused', detail(off));
    }
    const sus = await api('POST', `/users/${user.json.id}/suspend`, {});
    const status = run('passwd', ['-S', uname]).out;
    check(sus.ok && /^\S+ (L|LK) /.test(status), `suspending locks the account: ${status}`, detail(sus));
    await api('POST', `/users/${user.json.id}/unsuspend`, {});
  }

  begin('firewall');
  const fw = (await api('GET', '/firewall/status')).json;
  check(fw?.summary?.state === 'enabled', `the firewall is on, engine ${fw?.summary?.engine}, protecting ${JSON.stringify(fw?.summary?.protected_ports)}`, JSON.stringify(fw?.summary));
  const open = await api('POST', '/firewall/allow-port', { port: '18081', protocol: 'tcp' });
  const block = await api('POST', '/firewall/block-ip', { ip: '203.0.113.77', port: null, protocol: 'tcp' });
  const ruleset = run('nft', ['list', 'ruleset']).out;
  check(open.ok && block.ok && ruleset.includes('18081') && ruleset.includes('203.0.113.77'), 'a port opened and an address blocked, both in nftables', `${detail(open)} ${detail(block)}`);
  // Rules are numbered by position, so each delete renumbers the rest.
  for (let i = 0; i < 5; i += 1) {
    const ours = ((await api('GET', '/firewall/status')).json?.rules || []).find((r) => String(r.port) === '18081' || String(r.ip || '').startsWith('203.0.113.77'));
    if (!ours) break;
    await api('DELETE', `/firewall/rules/${ours.id}`);
  }
  const after = run('nft', ['list', 'ruleset']).out;
  check(!after.includes('18081') && !after.includes('203.0.113.77'), 'and removed again');

  begin('automatic updates');
  const upd = await api('GET', '/updates/status');
  check(upd.ok && upd.json?.returncode === 0, `the Updates page reads the package manager (${(upd.json?.stdout || '').split('\n')[0].slice(0, 80)})`, detail(upd));
  const auto = await api('POST', '/updates/os/auto', { enabled: true, mode: 'security', auto_reboot: false });
  const armed = IS_EL
    ? run('systemctl', ['is-enabled', 'dnf-automatic.timer']).out
    : sh('cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null').out;
  check(auto.ok && auto.json?.returncode === 0 && (IS_EL ? armed === 'enabled' : armed.includes('"1"')), `automatic security updates on (${armed.replace(/\s+/g, ' ').slice(0, 80)})`, `${detail(auto)} ${auto.json?.stderr || ''}`);
  await api('POST', '/updates/os/auto', { enabled: false, mode: 'security', auto_reboot: false });

  begin('Fail2ban addon');
  const f2b = await api('POST', '/addons/fail2ban/install', {});
  const f2bState = (await api('GET', '/fail2ban')).json;
  check(f2b.ok && f2bState?.service?.running, `installed and running (${f2bState?.service?.version}), jails ${(f2bState?.jails || []).filter((j) => j.running).map((j) => j.name).join(' ')}`, detail(f2b));
  const f2bOff = await api('POST', '/addons/fail2ban/uninstall', {});
  check(f2bOff.ok && !run('systemctl', ['is-active', 'fail2ban']).ok, 'uninstalled: fail2ban stopped', detail(f2bOff));

  begin('MCP addon');
  const mcpOn = await api('POST', '/addons/mcp/install', {});
  const token = await api('POST', '/mcp/tokens', { name: `smoke-${TAG}`, can_write: false, expires_days: 1 });
  if (check(mcpOn.ok && token.json?.token, 'installed, and a read-only token made', `${detail(mcpOn)} ${detail(token)}`)) {
    const rpc = (id, method, params) => api('POST', '/mcp', { jsonrpc: '2.0', id, method, params }, { bearer: token.json.token });
    const init = await rpc(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke', version: '1' } });
    const tools = await rpc(2, 'tools/list', {});
    const who = await rpc(3, 'tools/call', { name: 'whoami', arguments: {} });
    const sites = await rpc(4, 'tools/call', { name: 'list_websites', arguments: {} });
    check(init.json?.result?.serverInfo?.name === 'snpanel' && (tools.json?.result?.tools || []).length > 0, `an assistant connects: ${tools.json?.result?.tools?.length} tools`, `${init.text.slice(0, 150)}`);
    check((who.json?.result?.content?.[0]?.text || '').includes(ADMIN) && (sites.json?.result?.content?.[0]?.text || '').includes(phpDomain), 'and reads who it is and the websites', `${who.text.slice(0, 150)} ${sites.text.slice(0, 150)}`);
    await api('DELETE', `/mcp/tokens/${token.json.id}`);
  }
  await api('POST', '/addons/mcp/uninstall', {});

  begin('Applications addon');
  const appOn = await api('POST', '/addons/application/install', {});
  const rt = (await api('GET', '/site-runtimes/status')).json;
  check(appOn.ok && rt, `installed; Node majors ${JSON.stringify(rt?.node_majors)}, Docker ${rt?.docker?.installed ? rt.docker.version : 'not installed'}`, detail(appOn));
  const ni = await api('POST', '/site-runtimes/node-install', { major: '22' });
  check(ni.ok, `Node 22 for applications (${ni.status}: ${(ni.json?.stdout || ni.json?.message || detail(ni)).toString().split('\n').pop().slice(0, 100)})`, detail(ni));
  const app = await api('POST', '/site-apps', { name: `smk${TAG}`, kind: 'node', start_kind: 'node', start_arg: 'server.js', node_major: '22' });
  if (check(app.ok && app.json?.id, `a Node.js application on port ${app.json?.port}`, detail(app))) {
    const code = `require('http').createServer((q, r) => r.end('app-ok ' + process.version)).listen(${app.json.port}, '127.0.0.1');\n`;
    const fd = new FormData();
    fd.set('file', new Blob([code]), 'server.js');
    const upApp = await api('POST', `/maintenance/app-files/${app.json.id}/upload?path=`, undefined, { multipart: fd });
    const pkg = new FormData();
    pkg.set('file', new Blob([JSON.stringify({ name: `smk${TAG}`, version: '1.0.0', private: true, scripts: { start: 'node server.js' } })]), 'package.json');
    await api('POST', `/maintenance/app-files/${app.json.id}/upload?path=`, undefined, { multipart: pkg });
    const dep = await api('POST', `/site-apps/${app.json.id}/deploy`, {});
    await sleep(3000);
    const hit = run('curl', ['-s', '--max-time', '10', `http://127.0.0.1:${app.json.port}/`]);
    check(upApp.ok && dep.ok && hit.out.startsWith('app-ok'), `deployed under systemd and answering: ${hit.out.slice(0, 40)}`, `${detail(upApp)} ${detail(dep)} ${JSON.stringify(dep.json?.output || '').slice(0, 200)}`);
    const appSite = await api('POST', '/websites', { domain: `app-${TAG}.example.com`, app_type: 'application', app_id: app.json.id });
    if (appSite.json?.id) made.sites.push(appSite.json);
    const via = await webUntil(`app-${TAG}.example.com`, '/', (r) => r.body.startsWith('app-ok'));
    check(appSite.ok && via.body.startsWith('app-ok'), `a domain proxies to it (${via.code})`, detail(appSite));
    await api('POST', `/site-apps/${app.json.id}/control`, { action: 'stop' });
    if (appSite.json?.id) { await api('DELETE', `/websites/${appSite.json.id}?delete_files=true`); made.sites = made.sites.filter((x) => x.id !== appSite.json.id); }
    await api('DELETE', `/site-apps/${app.json.id}`);
  }
  if (process.env.SMOKE_DOCKER === '1') {
    const di = await api('POST', '/site-runtimes/docker-install', {}, { timeout: 1800000 });
    const dstat = (await api('GET', '/site-runtimes/status')).json?.docker;
    check(di.ok && dstat?.active, `Docker installed from the panel (${dstat?.version})`, detail(di));
  } else skip('Docker install', 'set SMOKE_DOCKER=1');
  await api('POST', '/addons/application/uninstall', {});

  begin('WordPress');
  const wpDomain = `wp-${TAG}.example.com`;
  const wp = await api('POST', '/websites', { domain: wpDomain, app_type: 'wordpress', install_wordpress: true, title: 'Smoke', admin_user: 'smokeadmin', admin_email: 'smoke@example.com', admin_password: secret(), php_version: newest });
  if (check(wp.ok && wp.json?.id, `WordPress installed (${wp.status})`, detail(wp))) {
    made.sites.push(wp.json);
    const home = await webUntil(wpDomain, '/', (r) => r.code === 200 && /wp-content|wp-includes/.test(r.body), { seconds: 30 });
    // Installed with an https:// site URL, so over plain HTTP wp-login.php
    // sends the browser there - WordPress's own redirect, not a failure.
    const signIn = (r) => (r.code === 200 && /user_login/.test(r.body)) || (r.code === 302 && r.location.startsWith(`https://${wpDomain}/wp-login.php`));
    const loginPage = await webUntil(wpDomain, '/wp-login.php', signIn, { seconds: 30 });
    check(/wp-content|wp-includes/.test(home.body), `its home page is WordPress (${home.code})`, home.body.replace(/\s+/g, ' ').slice(0, 160));
    check(signIn(loginPage), `and wp-login.php answers as WordPress (${loginPage.code}${loginPage.location ? ` to ${loginPage.location}` : ''})`, loginPage.body.replace(/\s+/g, ' ').slice(0, 160));
  }

  begin('malware scanning');
  const clam = process.env.SMOKE_CLAMAV === '1';
  const maldet = process.env.SMOKE_MALDET === '1';
  // The scanner first, for both: with it off, switching upload scanning on
  // records the wish and installs nothing ("Uploads will be scanned once the
  // malware scanner is on").
  let scanner = false;
  if (clam || maldet) {
    const on = await api('POST', '/malware/toggle', { enabled: true }, { timeout: 1800000 });
    // LMD, not `installed`: that is true as soon as the install has pulled in
    // ClamAV, while LMD is still arriving, and a scan started then takes the
    // ClamAV path and fails for want of the daemon.
    const st = await poll('/malware/status', (j) => j.lmd_installed, { every: 5000, limit: 1200000 });
    scanner = check(on.ok && st?.lmd_installed, `the malware scanner on: LMD installed`, `${detail(on)} ${JSON.stringify(st).slice(0, 200)}`);
  }
  if (clam && scanner) {
    const on = await api('POST', '/malware/upload-scan', { enabled: true }, { timeout: 1800000 });
    const st2 = await poll('/malware/status', (j) => j.clamd_running, { every: 5000, limit: 1200000 });
    if (check(on.ok && st2?.clamd_running, `upload scanning: clamd installed and running`, `${detail(on)} ${JSON.stringify(st2).slice(0, 200)}`)) {
      const eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
      const fd = new FormData();
      fd.set('file', new Blob([eicar]), 'eicar.txt');
      const bad = await api('POST', `/maintenance/files/${s.id}/upload?path=public_html`, undefined, { multipart: fd });
      check(!bad.ok && !existsSync(`${s.root_path}/public_html/eicar.txt`), `the EICAR test file is refused (${bad.status}: ${detail(bad).slice(0, 80)})`);
      const fine = new FormData();
      fine.set('file', new Blob(['nothing to see here\n']), `clean-${TAG}.txt`);
      const good = await api('POST', `/maintenance/files/${s.id}/upload?path=public_html`, undefined, { multipart: fine });
      check(good.ok && existsSync(`${s.root_path}/public_html/clean-${TAG}.txt`), `and a clean file goes through (${good.status})`, detail(good));
    }
    await api('POST', '/malware/upload-scan', { enabled: false });
  } else if (!clam) skip('ClamAV upload scanning', 'set SMOKE_CLAMAV=1 (about 1.5 GB of memory)');
  if (maldet && scanner) {
    const scan = await api('POST', '/malware/run', { website_id: s.id });
    const sj = scan.json?.job_id ? await poll(`/malware/jobs/${scan.json.job_id}`, (j) => ['done', 'infected', 'error', 'interrupted'].includes(j.status), { every: 3000, limit: 1200000 }) : null;
    check(scan.ok && sj?.status === 'done', `a malware scan of the site (${sj?.status}, ${sj?.scanned} files)`, `${detail(scan)} ${sj?.error || ''}`);
  } else if (!maldet) skip('Maldet scan', 'set SMOKE_MALDET=1');
  if (clam || maldet) await api('POST', '/malware/toggle', { enabled: false });
}

async function cleanup() {
  begin('cleanup');
  for (const site of made.sites) {
    const r = await api('DELETE', `/websites/${site.id}?delete_files=true&delete_database=true`);
    const vhost = sh(`ls /etc/nginx/sites-enabled/${site.domain}.conf /etc/nginx/conf.d/${site.domain}.conf /etc/nginx/sites-available/${site.domain}.conf 2>/dev/null`).out;
    const logsLeft = sh(`ls /var/log/nginx/ | grep -F '${site.domain}.' || true`).out;
    check(r.ok && !vhost && !logsLeft && !existsSync(site.root_path), `${site.domain} deleted: vhost, files and logs gone`, `${r.status} vhost=${vhost} logs=${logsLeft}`);
  }
  for (const d of made.dbs) {
    const gone = run('mariadb', ['-N', '-e', `SHOW DATABASES LIKE '${d.db_name}'`]).out;
    check(!gone.includes(d.db_name), `database ${d.db_name} dropped with its site`);
  }
  for (const u of made.users) {
    const r = await api('DELETE', `/users/${u.id}`);
    check(r.ok && !run('id', [u.username]).ok, `user ${u.username} deleted, Linux account too`, detail(r));
  }
}

try {
  await main();
} catch (e) {
  check(false, `the run itself: ${e.stack || e}`);
} finally {
  try { await cleanup(); } catch (e) { check(false, `cleanup: ${e}`); }
  const pass = results.filter((r) => r.ok).length;
  const fail = results.filter((r) => !r.ok && !r.skip).length;
  const skipped = results.filter((r) => r.skip).length;
  out(`\n================================================\n  passed: ${pass}   failed: ${fail}   skipped: ${skipped}`);
  writeFileSync('/root/smoke-result.json', JSON.stringify(results, null, 1));
  process.exit(fail ? 1 : 0);
}
