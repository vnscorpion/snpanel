// S3 destinations against Garage (https://garagehq.deuxfleurs.fr), an S3
// store that checks every signature - a listing's too, which moto cannot:
// it refuses botocore's own ListObjectsV2.
//
//     node s3garage.mjs
//
// Runs on the box, as root. Starts a one-node Garage with
// garage-setup.sh, beside this file, makes a user of its own with a site holding 20 MB
// gzip cannot shrink, and:
//
//   - adds Garage as a destination, which the panel tests as it saves;
//   - runs a stamped schedule with a retention of one: the archive goes up
//     in parts and comes back byte for byte;
//   - runs it again a minute later: the bucket keeps the newest of the
//     family and loses the older - as the folder here does - while another
//     account's archive in the same folder, and an older copy of this
//     family, are judged by name alone.
//
// Removes the schedule, the destination, the user, its archives and Garage.
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { BASE, logIn } from './capture.mjs';

const NAME = 's3garage';
const DOMAIN = `s3g${Date.now() % 1000000}.example.com`;
const S3 = 'http://127.0.0.1:3900';
const FOLDER = 'nightly';
const USER_DIR = `/var/backups/snpanel/users/${NAME}`;

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const nextMinute = async () => { const now = new Date(); await sleep((61 - now.getSeconds()) * 1000); };

writeFileSync('/tmp/s3garage.py', `
import json, sys, boto3, botocore
url, key, secret, cmd = sys.argv[1:5]
s3 = boto3.client("s3", endpoint_url=url, region_name="garage", aws_access_key_id=key,
                  aws_secret_access_key=secret, config=botocore.config.Config(s3={"addressing_style": "path"}))
if cmd == "list":
    out = s3.list_objects_v2(Bucket="backups", Prefix=sys.argv[5])
    print(json.dumps(sorted(o["Key"] for o in out.get("Contents", []))))
elif cmd == "get":
    s3.download_file("backups", sys.argv[5], sys.argv[6])
    print("ok")
elif cmd == "put":
    s3.put_object(Bucket="backups", Key=sys.argv[5], Body=b"not an archive")
    print("ok")
`);
const SETUP = fileURLToPath(new URL('garage-setup.sh', import.meta.url));
const started = run('/bin/bash', [SETUP, 'start']).trim().split('\n');
let creds = {};
try { creds = JSON.parse(started[started.length - 1]); } catch {}
const py = (...args) => run('python3', ['/tmp/s3garage.py', S3, creds.key, creds.secret, ...args]);
check(creds.key && creds.secret, `Garage is up, with a key and a bucket (${started.slice(-1)})`);

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true });
await logIn(context);
const csrf = async () => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const api = async (method, path, data) => context.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': await csrf() }, timeout: 600000 });
const json = async (res) => res.json().catch(() => ({}));
const schedules = async () => json(await api('GET', '/maintenance/backup-schedules'));
const runScheduler = async (id) => {
  run('systemctl', ['start', 'snpanel-backup-scheduler.service']);
  return (await schedules()).find((s) => s.id === id);
};
const keyOf = (message) => /s3:\/\/[^/]+\/(\S+?\.tar\.gz)/.exec(message || '')?.[1];

let userId = null;
let siteId = null;
let targetId = null;
let scheduleId = null;
run('systemctl', ['stop', 'snpanel-backup-scheduler.timer']);
try {
  const old = (await json(await api('GET', '/users?usage=0'))).find((u) => u.username === NAME);
  if (old) await api('DELETE', `/users/${old.id}`);
  run('rm', ['-rf', USER_DIR]);
  userId = (await json(await api('POST', '/users', { username: NAME, email: `${NAME}@example.com`, password: 's3 garage password 1', role: 'end_user', website_limit: 2, storage_limit_mb: 500 }))).id;
  const site = await json(await api('POST', '/websites', { domain: DOMAIN, app_type: 'static', owner_id: userId }));
  siteId = site.id;
  run('dd', ['if=/dev/urandom', `of=${site.root_path}/noise.bin`, 'bs=1M', 'count=20', 'status=none']);
  run('chown', ['--reference', site.root_path, `${site.root_path}/noise.bin`]);
  check(userId && siteId, `a user with a site holding 20 MB (${DOMAIN})`);

  const saved = await api('POST', '/maintenance/s3-targets', { name: 'garage-check', endpoint: S3, region: 'garage', bucket: 'backups', prefix: FOLDER, access_key: creds.key, secret_key: creds.secret, path_style: true });
  const target = await json(saved);
  targetId = target.id;
  check(saved.ok() && targetId, `Garage is saved as a destination (${saved.status()})`);
  const tested = await api('POST', `/maintenance/s3-targets/${targetId}/test`);
  check(tested.ok(), `and its test writes an object and removes it again (${tested.status()} ${(await tested.text()).slice(0, 120)})`);

  // Judged by name: an older copy of this family goes, another account's stays.
  const olderOfFamily = `${FOLDER}/user-${NAME}-20200101000000.tar.gz`;
  const otherAccount = `${FOLDER}/user-${NAME}x-20200101000000.tar.gz`;
  py('put', olderOfFamily);
  py('put', otherAccount);

  scheduleId = (await json(await api('POST', '/maintenance/backup-schedules', { user_ids: [userId], schedule: '* * * * *', s3_target_id: targetId, name_style: 'timestamp', retention: 1 }))).id;
  let schedule = await runScheduler(scheduleId);
  const first = keyOf(schedule?.last_message);
  check(schedule?.last_status === 'ok' && first, `the first run uploads (${schedule?.last_status}: ${schedule?.last_message})`);
  py('get', first || 'none', '/tmp/s3garage-down.tar.gz');
  check(first && sha('/tmp/s3garage-down.tar.gz') === sha(`${USER_DIR}/${first.split('/').pop()}`), 'in parts, and back byte for byte');
  let listed = JSON.parse(py('list', `${FOLDER}/`) || '[]');
  check(listed.includes(first) && !listed.includes(olderOfFamily), `the older copy of the family is gone already (${listed.join(' ')})`);

  await nextMinute();
  schedule = await runScheduler(scheduleId);
  const second = keyOf(schedule?.last_message);
  listed = JSON.parse(py('list', `${FOLDER}/`) || '[]');
  check(schedule?.last_status === 'ok' && second && second !== first, `a minute later, a new stamp (${second})`);
  check(listed.includes(second) && !listed.includes(first), `a retention of one keeps the newest in the bucket and removes the older (${listed.join(' ')})`);
  check(listed.includes(otherAccount), "another account's archive in the same folder is left alone");
} finally {
  if (scheduleId) await api('DELETE', `/maintenance/backup-schedules/${scheduleId}`);
  if (targetId) await api('DELETE', `/maintenance/s3-targets/${targetId}`);
  if (siteId) await api('DELETE', `/websites/${siteId}?delete_files=true`);
  if (userId) await api('DELETE', `/users/${userId}`);
  run('rm', ['-rf', USER_DIR, '/tmp/s3garage-down.tar.gz', '/tmp/s3garage.py']);
  run('systemctl', ['start', 'snpanel-backup-scheduler.timer']);
  run('/bin/bash', [SETUP, 'stop']);
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
