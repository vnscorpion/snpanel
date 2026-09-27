// A restore from another server, given by hand - FTP, FTPS and SFTP - end to
// end on the box, as root, through the API the Restore tab calls.
//
//     node restore-connection-check.mjs          (on the box, as root)
//
// Sets up what it needs and takes it all away again: vsftpd, installed for
// the run and purged after (with anything it pulled in), listening on
// 127.0.0.1:2121 with the machine's self-signed "snakeoil" certificate and
// vsftpd's own insistence that data connections resume the control one's TLS
// session; a PAM service of its own; and a throwaway panel account whose
// login is used over FTP and SFTP, holding a copy of demo's newest backup.
// Checks that a customer is refused; a password with a line break is
// refused; FTP lists the folder and says why when the password or the folder
// is wrong; FTPS asks to trust the self-signed certificate, lists with it
// trusted, and asks again when another was trusted - a restore with that one
// failing, and saying why; SFTP lists and says its host key; and demo is
// restored from each of the three, the job never showing the password.
// Every generated password stays in this process.
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import { chownSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const NAME = 'rcheck';
const PASSWORD = `R-${randomBytes(15).toString('base64url')}`;
const FTP_PORT = 2121;
const UNIT = 'snpanel-ftp-check';
const CONF = '/etc/vsftpd-snpanel-check.conf';
const PAM = '/etc/pam.d/snpanel-ftp-check';
const SNAKEOIL = '/etc/ssl/certs/ssl-cert-snakeoil.pem';

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const packages = () => new Set(run('dpkg-query', ['-W', '-f=${Package} ${Status}\\n']).split('\n')
  .filter((l) => l.endsWith('install ok installed')).map((l) => l.split(' ')[0]));

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

const had = packages();
let userId = null;
const connection = (protocol, extra = {}) => ({
  protocol, host: '127.0.0.1', port: protocol === 'sftp' ? 22 : FTP_PORT,
  username: NAME, password: PASSWORD, folder: protocol === 'sftp' ? '/backups' : `/home/${NAME}/backups`, ...extra,
});
async function restoreFrom(conn, file) {
  const started = await admin('POST', '/maintenance/restore/jobs', { source: 'connection', connection: conn, files: [file] });
  if (!started.ok) return { started, job: null };
  let job = started.json;
  for (let i = 0; i < 240 && job?.status === 'running'; i += 1) {
    await sleep(1500);
    job = (await admin('GET', `/maintenance/restore/jobs/${started.json.id}`)).json;
  }
  return { started, job };
}

try {
  // ---------------------------------------------------------------- the FTP server
  run('apt-get', ['install', '-y', '-q', '--no-install-recommends', 'vsftpd', 'ssl-cert']);
  run('systemctl', ['disable', '--now', 'vsftpd']);
  check(existsSync('/usr/sbin/vsftpd') && existsSync(SNAKEOIL), 'vsftpd installed for the run, with the machine\'s self-signed certificate');
  writeFileSync(PAM, 'auth required pam_unix.so\naccount required pam_unix.so\nsession required pam_unix.so\n');
  writeFileSync(CONF, [
    'listen=YES', 'listen_ipv6=NO', 'listen_address=127.0.0.1', `listen_port=${FTP_PORT}`, 'background=NO',
    'anonymous_enable=NO', 'local_enable=YES', 'write_enable=NO', 'chroot_local_user=NO',
    `pam_service_name=${UNIT}`, 'userlist_enable=NO', 'seccomp_sandbox=NO', 'xferlog_enable=NO',
    'pasv_enable=YES', 'pasv_min_port=40000', 'pasv_max_port=40100',
    'ssl_enable=YES', 'allow_anon_ssl=NO', 'force_local_data_ssl=NO', 'force_local_logins_ssl=NO', 'require_ssl_reuse=YES',
    `rsa_cert_file=${SNAKEOIL}`, 'rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key',
    'secure_chroot_dir=/var/run/vsftpd/empty', '',
  ].join('\n'));
  mkdirSync('/var/run/vsftpd/empty', { recursive: true });
  run('systemd-run', [`--unit=${UNIT}`, '--quiet', '/usr/sbin/vsftpd', CONF]);
  await sleep(1500);
  check(run('systemctl', ['is-active', UNIT]).trim() === 'active', `vsftpd listens on 127.0.0.1:${FTP_PORT}`);

  // ---------------------------------------------------------------- an account holding a backup
  const users = async () => (await admin('GET', '/users?usage=0')).json || [];
  for (const old of (await users()).filter((u) => u.username === NAME)) await admin('DELETE', `/users/${old.id}`);
  userId = (await admin('POST', '/users', { username: NAME, email: `${NAME}@example.invalid`, password: PASSWORD, role: 'end_user', website_limit: 1, storage_limit_mb: 500 })).json?.id;
  const local = ((await admin('GET', '/maintenance/restore/local')).json?.items || [])
    .filter((i) => i.valid && i.username === 'demo')
    .sort((a, b) => String(b.modified).localeCompare(String(a.modified)));
  check(!!userId && local.length > 0, `a throwaway account ${NAME}, and a backup of demo to put on its server (${local[0]?.filename})`);
  const FILE = 'user-demo-20260101000000.tar.gz';
  const folder = `/home/${NAME}/backups`;
  mkdirSync(folder, { recursive: true });
  copyFileSync(local[0].backup_file, `${folder}/${FILE}`);
  const owner = Number(run('id', ['-u', NAME]).trim());
  const group = Number(run('id', ['-g', NAME]).trim());
  chownSync(folder, owner, group);
  chownSync(`${folder}/${FILE}`, owner, group);

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
  check(answer.ok && listed.some((i) => i.name === FILE && i.username === 'demo' && i.valid && i.size > 0),
    `FTP lists the folder: ${listed.map((i) => i.name).join(', ')}`);
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftp', { password: 'wrong-password' }));
  check(answer.status === 502 && /refused the sign-in: 530/.test(answer.text), `a wrong password is said as the server said it (${short(answer)})`);
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftp', { folder: '/nowhere' }));
  check(answer.status === 502 && /cannot open the folder: 550/.test(answer.text), `a folder that is not there too (${short(answer)})`);

  // ---------------------------------------------------------------- FTPS
  const expected = new X509Certificate(readFileSync(SNAKEOIL)).fingerprint256.replace(/:/g, '').toLowerCase();
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftps'));
  check(answer.ok && answer.json?.untrusted?.fingerprint === expected && answer.json.items.length === 0,
    `FTPS with a self-signed certificate asks to trust it, by its SHA-256 (${answer.json?.untrusted?.fingerprint?.slice(0, 16)}...)`);
  answer = await admin('POST', '/maintenance/restore/connection', connection('ftps', { certificate: expected }));
  check(answer.ok && (answer.json?.items || []).some((i) => i.name === FILE),
    'trusted, it lists the folder - encrypted, the data connections resuming the TLS session as vsftpd insists');
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
    `SFTP lists the folder and says its host key (${answer.json?.host_key?.type} ${hostKey?.slice(0, 20)}...)`);

  // ---------------------------------------------------------------- restored from each
  for (const [label, conn] of [
    ['FTPS', connection('ftps', { certificate: expected })],
    ['SFTP', connection('sftp', { host_key: hostKey })],
    ['FTP', connection('ftp')],
  ]) {
    const { started, job } = await restoreFrom(conn, FILE);
    const item = job?.items?.[0];
    check(started.ok && job?.status === 'done' && job.done === 1 && item?.username === 'demo',
      `demo restored from ${label} (${job?.target_name}: ${item?.status} ${item?.message || `${item?.websites} website(s)`})`);
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
  if (userId) await admin('DELETE', `/users/${userId}`);
  const added = [...packages()].filter((p) => !had.has(p));
  if (added.length) run('apt-get', ['purge', '-y', '-q', ...added]);
  console.log(`      removed again: vsftpd's run, its PAM service, ${NAME}${added.length ? `, and ${added.join(' ')}` : ''}`);
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
