// A customer's own SFTP accounts, end to end on the box, as root - the API
// the SFTP page calls, and the panel's own SFTP client (a backup
// destination) as the one that signs in:
//
//   - an account `<owner>_dev` shut into a site's public_html: the owner's
//     UID, the sub-account group, its unit active, the folder mounted in a
//     root-owned jail;
//   - it signs in and writes in its folder, and what it uploads is the
//     owner's; it cannot write at the jail's top, nor reach /home;
//   - a new password: the old one no longer signs in, the new one does;
//   - a folder that is a link is refused; a folder swapped for a link after
//     the account was made is not mounted when its unit starts again;
//   - deleted: the account, its unit and its jail gone, the site's files
//     there; the owner deleted: their accounts go with them.
//
//     node sftp-accounts-check.mjs          (on the box, as root)
//
// Removes the users, destinations and accounts it made.
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chownSync, existsSync, lstatSync, readFileSync, readdirSync, renameSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';

const BASE = process.env.PANEL_BASE || 'https://127.0.0.1:2222';
const OWNER = 'sftpown';
const DOMAIN = `so${Date.now() % 1000000}.example.com`;

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return `!${e.status} ${String(e.stdout || '')}${String(e.stderr || '')}`; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mounted = (point) => readFileSync('/proc/self/mountinfo', 'utf8').split('\n').some((line) => line.split(' ')[4] === point);

const jar = new Map();
async function api(method, path, body) {
  const headers = {};
  let payload;
  if (path === '/auth/login') { headers['Content-Type'] = 'application/x-www-form-urlencoded'; payload = new URLSearchParams(body).toString(); }
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  if (payload !== undefined) headers['Content-Length'] = Buffer.byteLength(payload);
  headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  if (!['GET', 'HEAD'].includes(method) && jar.get('snpanel_csrf')) headers['X-CSRF-Token'] = jar.get('snpanel_csrf');
  return new Promise((resolve, reject) => {
    const req = https.request(new URL(`${BASE}/api${path}`), { method, headers, rejectUnauthorized: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        for (const c of res.headers['set-cookie'] || []) { const [pair] = c.split(';'); const i = pair.indexOf('='); jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim()); }
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null; try { json = JSON.parse(text); } catch {}
        resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, json, text });
      });
    });
    req.setTimeout(600000, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}
const short = (r) => `${r.status} ${(r.text || '').slice(0, 160)}`;

// The panel's SFTP client, pointed at an account: a destination, tested.
const targets = [];
async function signIn(username, password, remotePath) {
  const name = `sftp-check-${targets.length}`;
  const added = await api('POST', '/maintenance/sftp-targets', { name, host: '127.0.0.1', port: 22, username, password, private_key: null, remote_path: remotePath });
  if (added.json?.id) targets.push(added.json.id);
  return api('POST', `/maintenance/sftp-targets/${added.json?.id}/test`);
}

const login = readFileSync('/root/login.txt', 'utf8');
const signedIn = await api('POST', '/auth/login', { username: /^User: (.+)$/m.exec(login)[1].trim(), password: /^Password: (.+)$/m.exec(login)[1].trim() });
check(signedIn.ok, `the administrator signs in (${signedIn.status})`);
let userId = null;
let web = '';
try {
  const old = ((await api('GET', '/users?usage=0')).json || []).find((u) => u.username === OWNER);
  if (old) await api('DELETE', `/users/${old.id}`);
  userId = (await api('POST', '/users', { username: OWNER, email: `${OWNER}@example.com`, password: `So-${randomBytes(12).toString('base64url')}`, role: 'end_user', website_limit: 2, storage_limit_mb: 500 })).json?.id;
  const site = (await api('POST', '/websites', { domain: DOMAIN, app_type: 'static', owner_id: userId })).json;
  web = `${site.root_path}/public_html`;
  const ownerStat = statSync(site.root_path);
  writeFileSync(`${web}/marker.html`, 'mine');
  chownSync(`${web}/marker.html`, ownerStat.uid, ownerStat.gid);
  const folder = `${DOMAIN}/public_html`;
  check(userId && existsSync(web), `a user with a site (${DOMAIN})`);

  // ---------------------------------------------------------------- made
  const made = await api('POST', `/users/${userId}/sftp/accounts`, { name: 'dev', directory: folder, generate: true });
  const account = `${OWNER}_dev`;
  let password = made.json?.password;
  check(made.ok && made.json?.username === account && password?.length >= 12, `an account ${account} is made, its password shown once (${made.status})`);
  const pw = run('getent', ['passwd', account]).trim().split(':');
  const ownerPw = run('getent', ['passwd', OWNER]).trim().split(':');
  check(pw[2] === ownerPw[2] && pw[3] === ownerPw[3] && pw[5] === '/public_html', `with the owner's UID and GID, its home the folder as seen inside (${pw.join(':')})`);
  check(run('id', ['-nG', account]).split(/\s+/).includes('snpanel-sftp-sub'), 'in the group sshd matches');
  const unit = `snpanel-sftp-${account}.service`;
  check(run('systemctl', ['is-active', unit]).trim() === 'active', `its unit is active (${unit})`);
  const jail = `/srv/sftp/${account}`;
  const point = `${jail}/public_html`;
  check(mounted(point) && existsSync(`${point}/marker.html`), `the folder is mounted in its jail (${point})`);
  const jailStat = statSync(jail);
  check(jailStat.uid === 0 && (jailStat.mode & 0o777) === 0o755, 'the jail is root\'s, 0755');
  const listed = (await api('GET', `/users/${userId}/sftp/accounts`)).json;
  check(listed?.items?.[0]?.home === '/public_html' && listed.items[0].directory === folder, `listed with its folder (${JSON.stringify(listed?.items?.[0] || {}).slice(0, 120)})`);

  // ---------------------------------------------------------------- signs in, confined
  let tested = await signIn(account, password, '/public_html');
  check(tested.ok && tested.json?.removed, `it signs in over SFTP and writes in its folder (${short(tested)})`);
  const up = await api('POST', '/maintenance/user-backup', { user_id: userId, target_id: targets.at(-1) });
  let job = up.json;
  for (let i = 0; job?.job_id && i < 120 && !['done', 'error'].includes(job.status); i += 1) { await sleep(1000); job = (await api('GET', `/maintenance/backup-jobs/${job.job_id}`)).json; }
  const uploaded = readdirSync(web).find((f) => f.endsWith('.tar.gz'));
  check(uploaded && statSync(`${web}/${uploaded}`).uid === ownerStat.uid, `what it uploads lands in the site, the owner's (${uploaded} ${job?.status})`);
  tested = await signIn(account, password, '/');
  check(!tested.ok, `it cannot write at the jail's top (${short(tested)})`);
  tested = await signIn(account, password, '/home');
  check(!tested.ok, `nor reach /home (${short(tested)})`);

  // ---------------------------------------------------------------- a new password
  const renewed = await api('POST', `/users/${userId}/sftp/accounts/${made.json.id}/password`, { generate: true });
  check(renewed.ok && renewed.json?.password && renewed.json.password !== password, `a new password (${renewed.status})`);
  tested = await signIn(account, password, '/public_html');
  check(!tested.ok, `the old one no longer signs in (${tested.status})`);
  password = renewed.json.password;
  tested = await signIn(account, password, '/public_html');
  check(tested.ok, `the new one does (${tested.status})`);

  // ---------------------------------------------------------------- links
  symlinkSync('/etc', `${web}/escape`);
  const linked = await api('POST', `/users/${userId}/sftp/accounts`, { name: 'bad', directory: `${folder}/escape`, generate: true });
  check(linked.status === 400 && /link/.test(linked.text), `a folder that is a link is refused (${short(linked)})`);
  unlinkSync(`${web}/escape`);
  // Swapped after it was made: the next mount does not follow it.
  run('systemctl', ['stop', unit]);
  check(!mounted(point), 'stopped, the unit unmounts');
  renameSync(web, `${web}.real`);
  symlinkSync('/etc', web);
  run('systemctl', ['start', unit]);
  check(!mounted(point) && !existsSync(`${point}/passwd`), 'a folder swapped for a link is not mounted when the unit starts again');
  unlinkSync(web);
  renameSync(`${web}.real`, web);
  run('systemctl', ['reset-failed', unit]);
  run('systemctl', ['start', unit]);
  check(mounted(point) && existsSync(`${point}/marker.html`), 'put back, it mounts again');

  // ---------------------------------------------------------------- deleted
  const gone = await api('DELETE', `/users/${userId}/sftp/accounts/${made.json.id}`);
  check(gone.ok && run('getent', ['passwd', account]).startsWith('!'), `deleted, the account is gone (${gone.status})`);
  check(!existsSync(`/etc/systemd/system/${unit}`) && !mounted(point) && !existsSync(jail), 'its unit, its mount and its jail are gone');
  check(existsSync(`${web}/marker.html`), 'the site\'s files are all there');

  // ---------------------------------------------------------------- with its owner
  const two = await api('POST', `/users/${userId}/sftp/accounts`, { name: 'two', directory: '.', generate: true });
  check(two.ok && mounted(`/srv/sftp/${OWNER}_two/${OWNER}`), `an account of the whole home, seen as /${OWNER} (${two.status})`);
  await api('DELETE', `/users/${userId}`);
  userId = null;
  check(run('getent', ['passwd', `${OWNER}_two`]).startsWith('!') && !existsSync(`/srv/sftp/${OWNER}_two`) && !existsSync(`/etc/systemd/system/snpanel-sftp-${OWNER}_two.service`),
    'the owner deleted, their accounts go with them');
} finally {
  if (web && existsSync(`${web}.real`)) { try { if (lstatSync(web).isSymbolicLink()) unlinkSync(web); } catch {} renameSync(`${web}.real`, web); }
  for (const id of targets) await api('DELETE', `/maintenance/sftp-targets/${id}`);
  if (userId) await api('DELETE', `/users/${userId}`);
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
