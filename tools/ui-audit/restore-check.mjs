// The Backups page's destinations and restore, end to end on the box, as
// root - no browser, the API the page calls:
//
//   - an SFTP account of its own (a random password, never printed) as a
//     destination: added, tested (which pins the host key), edited with the
//     password left blank - kept - and tested again;
//   - a user of its own with a site and a marker file, backed up to it;
//   - the destination's archives listed, the account read from the name;
//   - the user deleted, then restored from the destination as a job: the
//     archive is fetched, restored and removed again, and the user, the
//     site and the marker are back;
//   - a restore from this server's own folder, over the user as it is;
//   - a name the destination does not have fails that one archive, and the
//     job still finishes;
//   - a destination a schedule uploads to is not deleted;
//   - with Garage (/opt/snpanel-probe/garage, see garage-setup.sh) the same
//     from an S3 bucket.
//
//     node restore-check.mjs          (on the box, as root)
//
// Removes the users, destinations, schedule, archives, the SFTP account and
// Garage it made.
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const BASE = process.env.PANEL_BASE || 'https://127.0.0.1:2222';
const NAME = 'rstcheck';
const DOMAIN = `rst${Date.now() % 1000000}.example.com`;
const SFTP_USER = 'sftpbkcheck';
const REMOTE = `/home/${SFTP_USER}/backups`;
const MARKER = `restored ${randomBytes(6).toString('hex')}\n`;
const BACKUPS = '/var/backups/snpanel/users';
const GARAGE = '/opt/snpanel-probe/garage';
const SETUP = fileURLToPath(new URL('garage-setup.sh', import.meta.url));

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args, input) => {
  try { return execFileSync(cmd, args, { encoding: 'utf8', input, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const login = readFileSync('/root/login.txt', 'utf8');
const jar = new Map();
async function api(method, path, body) {
  const headers = {};
  let payload;
  if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  else if (!['GET', 'HEAD', 'DELETE'].includes(method)) { headers['Content-Type'] = 'application/json'; payload = '{}'; }
  if (path === '/auth/login') { headers['Content-Type'] = 'application/x-www-form-urlencoded'; payload = new URLSearchParams(body).toString(); }
  if (payload !== undefined) headers['Content-Length'] = Buffer.byteLength(payload);
  headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  if (!['GET', 'HEAD'].includes(method) && jar.get('snpanel_csrf')) headers['X-CSRF-Token'] = jar.get('snpanel_csrf');
  return new Promise((resolve, reject) => {
    const req = https.request(new URL(`${BASE}/api${path}`), { method, headers, rejectUnauthorized: false }, (res) => {
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
}
const short = (r) => `${r.status} ${(r.text || '').slice(0, 160)}`;

async function backupJob(body) {
  const started = await api('POST', '/maintenance/user-backup', body);
  const id = started.json?.job_id;
  for (let i = 0; id && i < 300; i += 1) {
    const job = (await api('GET', `/maintenance/backup-jobs/${id}`)).json;
    if (job && ['done', 'error'].includes(job.status)) return job;
    await sleep(1000);
  }
  return started.json;
}

async function restoreJob(body) {
  const started = await api('POST', '/maintenance/restore/jobs', body);
  if (!started.ok) return { started };
  for (let i = 0; i < 600; i += 1) {
    const job = (await api('GET', `/maintenance/restore/jobs/${started.json.id}`)).json;
    if (job?.status === 'done') return { started, job };
    await sleep(1000);
  }
  return { started, job: null };
}

async function freshUser() {
  const old = ((await api('GET', '/users?usage=0')).json || []).find((u) => u.username === NAME);
  if (old) await api('DELETE', `/users/${old.id}`);
  run('rm', ['-rf', `${BACKUPS}/${NAME}`]);
  const user = (await api('POST', '/users', { username: NAME, email: `${NAME}@example.com`, password: `Rst-${randomBytes(12).toString('base64url')}`, role: 'end_user', website_limit: 2, storage_limit_mb: 500 })).json;
  const site = (await api('POST', '/websites', { domain: DOMAIN, app_type: 'static', owner_id: user?.id })).json;
  if (site?.root_path) {
    run('/bin/sh', ['-c', `cat > '${site.root_path}/marker.txt' && chown --reference='${site.root_path}' '${site.root_path}/marker.txt'`], MARKER);
  }
  return { user, site };
}

const markerBack = (site) => { try { return readFileSync(`${site.root_path}/marker.txt`, 'utf8') === MARKER; } catch { return false; } };
const restoreFolder = () => { try { return readdirSync(`${BACKUPS}/restore`); } catch { return []; } };

let sftpId = null;
let s3Id = null;
let scheduleId = null;
let garageUp = false;
const signedIn = await api('POST', '/auth/login', { username: /^User: (.+)$/m.exec(login)[1].trim(), password: /^Password: (.+)$/m.exec(login)[1].trim() });
check(signedIn.ok, `the administrator signs in (${signedIn.status})`);
try {
  // ---------------------------------------------------------------- an SFTP destination
  const sftpPassword = `Bk-${randomBytes(15).toString('base64url')}`;
  run('userdel', ['-r', SFTP_USER]);
  run('useradd', ['-m', '-s', '/bin/bash', SFTP_USER]);
  run('chpasswd', [], `${SFTP_USER}:${sftpPassword}\n`);
  run('install', ['-d', '-o', SFTP_USER, '-g', SFTP_USER, '-m', '0750', REMOTE]);
  for (const t of ((await api('GET', '/maintenance/sftp-targets')).json || []).filter((t) => t.name.startsWith('restore-check'))) await api('DELETE', `/maintenance/sftp-targets/${t.id}`);

  const added = await api('POST', '/maintenance/sftp-targets', { name: 'restore-check', host: '127.0.0.1', port: 22, username: SFTP_USER, password: sftpPassword, private_key: null, remote_path: REMOTE });
  sftpId = added.json?.id;
  check(added.ok && sftpId, `an SFTP destination is added (${added.status})`);
  const tested = await api('POST', `/maintenance/sftp-targets/${sftpId}/test`);
  check(tested.ok && tested.json?.ok && tested.json?.removed, `its test writes a file and removes it (${short(tested)})`);
  let row = ((await api('GET', '/maintenance/sftp-targets')).json || []).find((t) => t.id === sftpId);
  check(row?.host_key_fingerprint?.startsWith('SHA256:'), `the test pins the host key (${row?.host_key_type} ${row?.host_key_fingerprint})`);
  const edited = await api('PUT', `/maintenance/sftp-targets/${sftpId}`, { name: 'restore-check-2', host: '127.0.0.1', port: 22, username: SFTP_USER, password: '', private_key: '', remote_path: REMOTE });
  check(edited.ok && edited.json?.name === 'restore-check-2' && edited.json?.host_key_fingerprint === row?.host_key_fingerprint,
    `an edit renames it and keeps the pin (${short(edited)})`);
  const retested = await api('POST', `/maintenance/sftp-targets/${sftpId}/test`);
  check(retested.ok, `a blank password on the edit kept the saved one: the test still signs in (${retested.status})`);
  const badName = await api('PUT', `/maintenance/sftp-targets/${sftpId}`, { name: 'bad/name', host: '127.0.0.1', username: SFTP_USER });
  check(badName.status === 422, `a name with a slash is refused (${badName.status})`);

  // ---------------------------------------------------------------- back up, delete, restore
  let { user, site } = await freshUser();
  check(user?.id && site?.root_path && markerBack(site), `a user with a site and a marker file (${DOMAIN})`);
  const up = await backupJob({ user_id: user.id, target_id: sftpId });
  const uploaded = String(up?.remote_file || '').split('/').pop();
  check(up?.status === 'done' && uploaded.endsWith('.tar.gz'), `the user is backed up to the SFTP destination (${up?.status} ${up?.remote_file || up?.error || ''})`);
  const listed = await api('GET', `/maintenance/restore/sftp/${sftpId}`);
  const item = (listed.json?.items || []).find((i) => i.name === uploaded);
  check(listed.ok && item?.username === NAME && item?.valid && item?.size > 0, `the destination lists it, as ${NAME}'s (${short(listed)})`);

  await api('DELETE', `/users/${user.id}`);
  run('rm', ['-rf', `${BACKUPS}/${NAME}`]);
  check(!((await api('GET', '/users?usage=0')).json || []).some((u) => u.username === NAME) && !existsSync(site.root_path), 'the user and the site are gone');

  const before = restoreFolder();
  const { started, job } = await restoreJob({ source: 'sftp', target_id: sftpId, files: [uploaded] });
  check(started.ok && started.json?.status === 'running', `a restore from the destination starts (${short(started)})`);
  check(job?.done === 1 && job?.failed === 0 && job?.items?.[0]?.status === 'done', `and finishes: ${JSON.stringify(job?.items?.[0] || {}).slice(0, 200)}`);
  const back = ((await api('GET', '/users?usage=0')).json || []).find((u) => u.username === NAME);
  check(back && markerBack(site), 'the user, the site and the marker are back');
  check(restoreFolder().length === before.length, `the fetched archive is removed once restored (${restoreFolder().join(' ')})`);

  // ---------------------------------------------------------------- this server's folder
  const localUp = await backupJob({ user_id: back.id });
  check(localUp?.status === 'done', `a local backup (${localUp?.backup_file || localUp?.error})`);
  const local = await api('GET', '/maintenance/restore/local');
  const localItem = (local.json?.items || []).find((i) => i.backup_file === localUp?.backup_file);
  check(localItem?.valid && localItem?.username === NAME && localItem?.folder === NAME, `this server lists it from ${NAME}'s folder (${local.status})`);
  run('/bin/sh', ['-c', `echo changed > '${site.root_path}/marker.txt'`]);
  const localRestore = await restoreJob({ source: 'local', files: [localUp?.backup_file] });
  check(localRestore.job?.done === 1 && markerBack(site), `a restore from it puts the site back as it was (${localRestore.job?.items?.[0]?.status} ${localRestore.job?.items?.[0]?.message || ''})`);

  // ---------------------------------------------------------------- refusals
  const missing = await restoreJob({ source: 'sftp', target_id: sftpId, files: ['user-nobody-20200101000000.tar.gz'] });
  check(missing.job?.failed === 1 && missing.job?.items?.[0]?.status === 'error', `an archive the destination does not have fails, and the job ends (${missing.job?.items?.[0]?.message})`);
  const outside = await api('POST', '/maintenance/restore/jobs', { source: 'local', files: ['/etc/passwd'] });
  check(outside.status === 404, `a path outside the backup folder is refused (${outside.status})`);
  const sneaky = await api('POST', '/maintenance/restore/jobs', { source: 'sftp', target_id: sftpId, files: ['../x.tar.gz'] });
  check(sneaky.status === 400, `a remote name with a path in it is refused (${sneaky.status})`);
  scheduleId = (await api('POST', '/maintenance/backup-schedules', { user_ids: [back.id], schedule: '0 4 * * *', target_id: sftpId, name_style: 'timestamp', retention: 3 })).json?.id;
  const inUse = await api('DELETE', `/maintenance/sftp-targets/${sftpId}`);
  check(inUse.status === 409, `a destination a schedule uses is not deleted (${short(inUse)})`);
  await api('DELETE', `/maintenance/backup-schedules/${scheduleId}`);
  scheduleId = null;

  // ---------------------------------------------------------------- S3, when Garage is here
  if (existsSync(GARAGE) && existsSync(SETUP)) {
    const out = run('/bin/bash', [SETUP, 'start']).trim().split('\n');
    let creds = {};
    try { creds = JSON.parse(out[out.length - 1]); } catch {}
    garageUp = !!creds.key;
    const saved = await api('POST', '/maintenance/s3-targets', { name: 'restore-check-s3', endpoint: 'http://127.0.0.1:3900', region: 'garage', bucket: 'backups', prefix: 'nightly', access_key: creds.key, secret_key: creds.secret, path_style: true });
    s3Id = saved.json?.id;
    check(saved.ok && s3Id, `Garage is an S3 destination (${saved.status})`);
    const s3Up = await backupJob({ user_id: back.id, s3_target_id: s3Id });
    const key = /s3:\/\/[^/]+\/\S+\/(\S+?\.tar\.gz)/.exec(s3Up?.remote_file || '')?.[1];
    check(s3Up?.status === 'done' && key, `the user is backed up to the bucket (${s3Up?.remote_file || s3Up?.error})`);
    const s3List = await api('GET', `/maintenance/restore/s3/${s3Id}`);
    const s3Item = (s3List.json?.items || []).find((i) => i.name === key);
    check(s3List.ok && s3Item?.username === NAME && s3Item?.size > 0 && s3Item?.modified, `the bucket lists it with its size and date (${short(s3List)})`);
    await api('DELETE', `/users/${back.id}`);
    run('rm', ['-rf', `${BACKUPS}/${NAME}`]);
    const s3Restore = await restoreJob({ source: 's3', target_id: s3Id, files: [key] });
    check(s3Restore.job?.done === 1 && markerBack(site), `a restore from the bucket brings the user and the site back (${s3Restore.job?.items?.[0]?.status} ${s3Restore.job?.items?.[0]?.message || ''})`);
  } else {
    console.log('SKIP  no Garage here: the S3 restore is not tried');
  }
} finally {
  if (scheduleId) await api('DELETE', `/maintenance/backup-schedules/${scheduleId}`);
  const mine = ((await api('GET', '/users?usage=0')).json || []).find((u) => u.username === NAME);
  if (mine) await api('DELETE', `/users/${mine.id}`);
  run('rm', ['-rf', `${BACKUPS}/${NAME}`]);
  if (sftpId) await api('DELETE', `/maintenance/sftp-targets/${sftpId}`);
  if (s3Id) await api('DELETE', `/maintenance/s3-targets/${s3Id}`);
  if (garageUp) run('/bin/bash', [SETUP, 'stop']);
  run('userdel', ['-r', SFTP_USER]);
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
