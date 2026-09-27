// A restore from another server, given by hand - FTP, FTPS and SFTP - end to
// end on the box, as root, through the API the Restore tab calls. Debian,
// Ubuntu and AlmaLinux alike.
//
//     node restore-connection-check.mjs          (on the box, as root)
//
// Sets up what it needs and takes it all away again: vsftpd, installed for
// the run and removed after (with anything it pulled in), listening on
// 127.0.0.1:2121 with a self-signed certificate made for the run and
// vsftpd's own insistence that data connections resume the control one's TLS
// session; a PAM service of its own; a throwaway account `rsrc` with a
// website, backed up, whose backup is what is restored; and a throwaway
// account `rcheck` whose login is used over FTP and SFTP, holding a copy of
// that backup. Checks that a customer is refused; a password with a line
// break is refused; FTP lists the folder and says why when the password or
// the folder is wrong; FTPS asks to trust the self-signed certificate, lists
// with it trusted, and asks again when another was trusted - a restore with
// that one failing, and saying why; SFTP lists and says its host key; and
// rsrc is restored from each of the three, the job never showing the
// password. No account that was there before is touched. Every generated
// password stays in this process.
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import { chownSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const NAME = 'rcheck';
const SOURCE = 'rsrc';
const PASSWORD = `R-${randomBytes(15).toString('base64url')}`;
const SOURCE_PASSWORD = `S-${randomBytes(15).toString('base64url')}`;
const SITE = `rsrc-${randomBytes(3).toString('hex')}.example.com`;
const FTP_PORT = 2121;
const UNIT = 'snpanel-ftp-check';
const CONF = '/etc/vsftpd-snpanel-check.conf';
const PAM = '/etc/pam.d/snpanel-ftp-check';
const TLS_DIR = '/etc/snpanel-ftp-check';
const CERT = `${TLS_DIR}/cert.pem`;
const EL = existsSync('/usr/bin/rpm') && !existsSync('/usr/bin/dpkg');

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const packages = () => new Set(EL
  ? run('rpm', ['-qa', '--qf', '%{NAME}\\n']).split('\n').filter(Boolean)
  : run('dpkg-query', ['-W', '-f=${Package} ${Status}\\n']).split('\n')
    .filter((l) => l.endsWith('install ok installed')).map((l) => l.split(' ')[0]));
const install = (names) => (EL
  ? run('dnf', ['-y', '-q', 'install', ...names])
  : run('apt-get', ['install', '-y', '-q', '--no-install-recommends', ...names]));
const remove = (names) => (EL ? run('dnf', ['-y', '-q', 'remove', ...names]) : run('apt-get', ['purge', '-y', '-q', ...names]));

function session(base) {
  const jar = new Map();
  return async function api(method, path, body) {
    const headers = {};
    let payload;
    if (path === '/auth/login') { headers['Content-Type'] = 'application/x-www-form-urlencoded'; payload = new URLSearchParams(body).toString(); }
    else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
    else if (!['GET', 'HEAD', 'DELETE'].includes(method)) { headers['Content-Type'] = 'application/json'; payload = '{}'; }
    if (payload !== undefined) headers['Content-Length'] = Buffer.byteLength(payload);
    headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    if (!['GET', 'HEAD'].includes(method) && jar.get('snpanel_csrf')) headers['X-CSRF-Token'] = jar.get('snpanel_csrf');
    return new Promise((resolve, reject) => {
      const req = https.request(new URL(`${base}/api${path}`), { method, headers, rejectUnauthorized: false }, (res) => {
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
      req.setTimeout(600000, () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  };
}
const short = (r) => `${r.status} ${(r.text || '').slice(0, 170)}`;
const LOCAL = 'https://127.0.0.1:2222';
const admin = session(LOCAL);
const login = readFileSync('/root/login.txt', 'utf8');
check((await admin('POST', '/auth/login', { username: /^User: (.+)$/m.exec(login)[1].trim(), password: /^Password: (.+)$/m.exec(login)[1].trim() })).ok, 'the administrator signs in');
async function poll(path, done) {
  for (let i = 0; i < 400; i += 1) {
    const got = (await admin('GET', path)).json;
    if (got && done(got)) return got;
    await sleep(1500);
  }
  return null;
}

const had = packages();
const made = { users: [], backup: null };
let sftpPort = 22;
const connection = (protocol, extra = {}) => ({
  protocol, host: '127.0.0.1', port: protocol === 'sftp' ? sftpPort : FTP_PORT,
  username: NAME, password: PASSWORD, folder: protocol === 'sftp' ? '/backups' : `/home/${NAME}/backups`, ...extra,
});
async function restoreFrom(conn, file) {
  const started = await admin('POST', '/maintenance/restore/jobs', { source: 'connection', connection: conn, files: [file] });
  if (!started.ok) return { started, job: null };
  const job = started.json?.status === 'running'
    ? await poll(`/maintenance/restore/jobs/${started.json.id}`, (j) => j.status !== 'running')
    : started.json;
  return { started, job };
}
const users = async () => (await admin('GET', '/users?usage=0')).json || [];

try {
  // ---------------------------------------------------------------- the FTP server
  install(['vsftpd', 'openssl']);
  run('systemctl', ['disable', '--now', 'vsftpd']);
  mkdirSync(TLS_DIR, { recursive: true, mode: 0o700 });
  run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=snpanel-ftp-check',
    '-keyout', `${TLS_DIR}/key.pem`, '-out', CERT]);
  check(existsSync('/usr/sbin/vsftpd') && existsSync(CERT), `vsftpd installed for the run, and a self-signed certificate made for it (${EL ? 'dnf' : 'apt'})`);
  writeFileSync(PAM, 'auth required pam_unix.so\naccount required pam_unix.so\nsession required pam_unix.so\n');
  writeFileSync(CONF, [
    'listen=YES', 'listen_ipv6=NO', 'listen_address=127.0.0.1', `listen_port=${FTP_PORT}`, 'background=NO',
    'anonymous_enable=NO', 'local_enable=YES', 'write_enable=NO', 'chroot_local_user=NO',
    `pam_service_name=${UNIT}`, 'userlist_enable=NO', 'seccomp_sandbox=NO', 'xferlog_enable=NO',
    'pasv_enable=YES', 'pasv_min_port=40000', 'pasv_max_port=40100',
    'ssl_enable=YES', 'allow_anon_ssl=NO', 'force_local_data_ssl=NO', 'force_local_logins_ssl=NO', 'require_ssl_reuse=YES',
    `rsa_cert_file=${CERT}`, `rsa_private_key_file=${TLS_DIR}/key.pem`,
    'secure_chroot_dir=/var/run/vsftpd/empty', '',
  ].join('\n'));
  mkdirSync('/var/run/vsftpd/empty', { recursive: true });
  run('systemd-run', [`--unit=${UNIT}`, '--quiet', '/usr/sbin/vsftpd', CONF]);
  await sleep(1500);
  check(run('systemctl', ['is-active', UNIT]).trim() === 'active', `vsftpd listens on 127.0.0.1:${FTP_PORT}`);

  // ---------------------------------------------------------------- a backup, and an account holding it
  for (const old of (await users()).filter((u) => [NAME, SOURCE].includes(u.username))) await admin('DELETE', `/users/${old.id}`);
  const source = (await admin('POST', '/users', { username: SOURCE, email: `${SOURCE}@example.invalid`, password: SOURCE_PASSWORD, role: 'end_user', website_limit: 1, storage_limit_mb: 500 })).json;
  if (source?.id) made.users.push(source.id);
  const owner = session(LOCAL);
  await owner('POST', '/auth/login', { username: SOURCE, password: SOURCE_PASSWORD });
  const site = await owner('POST', '/websites', { domain: SITE, app_type: 'static' });
  const backup = source?.id ? await admin('POST', '/maintenance/user-backup', { user_id: source.id }) : null;
  const done = backup?.json?.job_id ? await poll(`/maintenance/backup-jobs/${backup.json.job_id}`, (j) => ['done', 'error'].includes(j.status)) : null;
  made.backup = done?.backup_file || null;
  check(!!source?.id && site.ok && done?.status === 'done' && existsSync(made.backup || ''),
    `a throwaway account ${SOURCE} with ${SITE}, backed up (${done?.status}: ${String(made.backup || done?.error || short(site)).split('/').pop()})`);

  const holder = (await admin('POST', '/users', { username: NAME, email: `${NAME}@example.invalid`, password: PASSWORD, role: 'end_user', website_limit: 1, storage_limit_mb: 500 })).json;
  if (holder?.id) made.users.push(holder.id);
  const sftp = holder?.id ? await admin('PUT', `/users/${holder.id}/sftp`, { enabled: true, password: PASSWORD }) : null;
  sftpPort = Number(sftp?.json?.ports?.[0] || 22);
  const FILE = `user-${SOURCE}-20260101000000.tar.gz`;
  const folder = `/home/${NAME}/backups`;
  mkdirSync(folder, { recursive: true });
  copyFileSync(made.backup, `${folder}/${FILE}`);
  const uid = Number(run('id', ['-u', NAME]).trim());
  const gid = Number(run('id', ['-g', NAME]).trim());
  chownSync(folder, uid, gid);
  chownSync(`${folder}/${FILE}`, uid, gid);
  check(!!holder?.id && sftp?.ok, `a throwaway account ${NAME} holding it, SFTP on port ${sftpPort}`);

  // ---------------------------------------------------------------- refused
  const customer = session(LOCAL);
  await customer('POST', '/auth/login', { username: NAME, password: PASSWORD });
  let answer = await customer('POST', '/maintenance/restore/connection', connection('ftp'));
  check(answer.status === 403, `a customer is refused (${answer.status})`);
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftp', { password: 'a\r\nDELE x' }));
  check(answer.status === 400 && /line breaks/.test(answer.text), `a password with a line break is refused (${short(answer)})`);

  // ---------------------------------------------------------------- FTP
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftp'));
  const listed = answer.json?.items || [];
  check(answer.ok && listed.some((i) => i.name === FILE && i.username === SOURCE && i.valid && i.size > 0),
    `FTP lists the folder: ${listed.map((i) => i.name).join(', ') || short(answer)}`);
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftp', { password: 'wrong-password' }));
  check(answer.status === 502 && /refused the sign-in: 530/.test(answer.text), `a wrong password is said as the server said it (${short(answer)})`);
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftp', { folder: '/nowhere' }));
  check(answer.status === 502 && /cannot open the folder: 550/.test(answer.text), `a folder that is not there too (${short(answer)})`);

  // ---------------------------------------------------------------- FTPS
  const expected = new X509Certificate(readFileSync(CERT)).fingerprint256.replace(/:/g, '').toLowerCase();
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftps'));
  check(answer.ok && answer.json?.untrusted?.fingerprint === expected && answer.json.items.length === 0,
    `FTPS with a self-signed certificate asks to trust it, by its SHA-256 (${answer.json?.untrusted?.fingerprint?.slice(0, 16) || short(answer)}...)`);
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftps', { certificate: expected }));
  check(answer.ok && (answer.json?.items || []).some((i) => i.name === FILE),
    `trusted, it lists the folder - encrypted, the data connections resuming the TLS session as vsftpd insists${answer.ok ? '' : ` (${short(answer)})`}`);
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftps', { certificate: 'ab'.repeat(32) }));
  check(answer.ok && answer.json?.untrusted?.fingerprint === expected && answer.json.items.length === 0,
    'with another certificate trusted - the server\'s replaced - it asks again, by the SHA-256 the server has now');
  const refused = await restoreFrom(connection('ftps', { certificate: 'ab'.repeat(32) }), FILE);
  const why = refused.job?.items?.[0];
  check(refused.started.ok && refused.job?.status === 'done' && refused.job.failed === 1 && why?.status === 'error'
    && why.message.includes(`not one this machine trusts (SHA-256 ${expected})`),
    `and a restore with it fails, saying why (${why?.message?.slice(0, 90)}...)`);

  // ---------------------------------------------------------------- SFTP
  answer = await admin('POST', '/maintenance/restore/connection', connection('sftp'));
  const hostKey = answer.json?.host_key?.fingerprint;
  check(answer.ok && (answer.json?.items || []).some((i) => i.name === FILE) && /^SHA256:/.test(hostKey || ''),
    `SFTP lists the folder and says its host key (${answer.ok ? `${answer.json?.host_key?.type} ${hostKey?.slice(0, 20)}...` : short(answer)})`);

  // ---------------------------------------------------------------- restored from each
  for (const [label, conn] of [
    ['FTPS', connection('ftps', { certificate: expected })],
    ['SFTP', connection('sftp', { host_key: hostKey })],
    ['FTP', connection('ftp')],
  ]) {
    const { started, job } = await restoreFrom(conn, FILE);
    const item = job?.items?.[0];
    check(started.ok && job?.status === 'done' && job.done === 1 && item?.username === SOURCE && item?.websites === 1,
      `${SOURCE} restored from ${label} (${job?.target_name}: ${item?.status} ${item?.message || `${item?.websites} website(s)`})`);
    check(!JSON.stringify(started.json || {}).includes(PASSWORD) && !JSON.stringify(job || {}).includes(PASSWORD),
      `the ${label} job never shows the password`);
  }
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.stack || err.message}`);
} finally {
  run('systemctl', ['stop', UNIT]);
  rmSync(CONF, { force: true });
  rmSync(PAM, { force: true });
  rmSync(TLS_DIR, { recursive: true, force: true });
  const listed = (await admin('GET', '/websites')).json;
  for (const site of (listed?.items || listed || []).filter((s) => s.domain === SITE)) {
    await admin('DELETE', `/websites/${site.id}?delete_files=true&delete_database=true`);
  }
  if (made.backup) await admin('DELETE', `/maintenance/user-backups?backup_file=${encodeURIComponent(made.backup)}`);
  for (const id of made.users) await admin('DELETE', `/users/${id}`);
  const left = (await users()).filter((u) => [NAME, SOURCE].includes(u.username)).length;
  const added = [...packages()].filter((p) => !had.has(p));
  if (added.length) remove(added);
  console.log(`      removed again: vsftpd's run, its PAM service and certificate, ${SITE}, ${SOURCE}'s backup, ${NAME} and ${SOURCE}${left ? ` (${left} still there!)` : ''}${added.length ? `, and ${added.join(' ')}` : ''}`);
  if (left) ok = false;
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
