// S3 as a backup destination, the names a schedule gives its archives, and
// the scheduler's uploads - against moto, an S3 server that checks every
// request's signature with botocore's own code.
//
//     node s3backup.mjs [out-dir]
//
// Runs on the box, as root: it starts moto_server, reads the bucket with
// boto3, runs the scheduler's unit and looks at the archives on disk. Makes a
// user of its own, `s3check`, and removes it and everything it made at the
// end. The scheduler's timer is stopped while it runs, so the only runs are
// its own, and started again after.
//
//   - A destination is added on the Destinations tab and tested on the spot.
//     Neither the list nor the database holds its secret. A wrong secret
//     fails the test with S3's own words; an edit that leaves the secret
//     blank keeps it.
//   - A full user backup of 20 MB goes to the bucket in two parts, byte for
//     byte.
//   - A schedule names its archives by the day of the week, by the user
//     alone - replaced by the next run - or by the date, pruned to its
//     retention; here and in the bucket, and no schedule's prune touches the
//     others' files.
//   - The scheduler uploads to an SFTP target again, and pins its host key.
//   - A destination a schedule uses cannot be deleted.
//
// The bucket's retention is s3garage.mjs's: it needs a listing, and moto's
// signature check refuses every ListObjectsV2, botocore's own included.
import { chromium } from 'playwright';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/s3backup';
mkdirSync(OUT, { recursive: true });
const NAME = 's3check';
const PORT = 5097;
const S3 = `http://127.0.0.1:${PORT}`;
const BUCKET = 'snpanel-backups';
const FOLDER = 'nightly';
const DOMAIN = `s3c${Date.now() % 1000000}.example.com`;
const USER_DIR = `/var/backups/snpanel/users/${NAME}`;

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args, env) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: env ? { ...process.env, ...env } : process.env }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const local = () => (existsSync(USER_DIR) ? readdirSync(USER_DIR).sort() : []);
const today = run('date', ['+%Y-%m-%d']).trim();
const weekday = run('date', ['+%A']).trim().toLowerCase();

// ------------------------------------------------------------------ the store
writeFileSync('/tmp/s3check.py', `
import json, sys, boto3, botocore
url, key, secret, cmd = sys.argv[1:5]
cfg = botocore.config.Config(s3={"addressing_style": "path"})
def s3(k, s):
    return boto3.client("s3", endpoint_url=url, region_name="us-east-1", aws_access_key_id=k, aws_secret_access_key=s, config=cfg)
if cmd == "setup":
    # The first four requests are let through unsigned: the key, its
    # permission and the bucket. Every request after them must be signed.
    iam = boto3.client("iam", endpoint_url=url, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    iam.create_user(UserName="backup")
    made = iam.create_access_key(UserName="backup")["AccessKey"]
    iam.put_user_policy(UserName="backup", PolicyName="s3", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}))
    s3("x", "x").create_bucket(Bucket=sys.argv[5])
    print(json.dumps({"key": made["AccessKeyId"], "secret": made["SecretAccessKey"]}))
elif cmd == "head":
    # HeadObject, not a listing: moto's signature check refuses botocore's
    # own ListObjectsV2 requests.
    try:
        o = s3(key, secret).head_object(Bucket=sys.argv[5], Key=sys.argv[6])
        print(json.dumps({"size": o["ContentLength"], "etag": o["ETag"]}))
    except botocore.exceptions.ClientError as e:
        print(json.dumps({"missing": e.response["Error"]["Code"]}))
elif cmd == "get":
    s3(key, secret).download_file(sys.argv[5], sys.argv[6], sys.argv[7])
    print("ok")
`);
const moto = spawn('moto_server', ['-H', '127.0.0.1', '-p', String(PORT)], { env: { ...process.env, INITIAL_NO_AUTH_ACTION_COUNT: '4' }, stdio: 'ignore' });
for (let i = 0; i < 100; i++) {
  if (run('curl', ['-s', '-o', '/dev/null', '-w', '%{http_code}', `${S3}/moto-api/`]).trim() === '200') break;
  await sleep(200);
}
let creds = JSON.parse(run('python3', ['/tmp/s3check.py', S3, 'x', 'x', 'setup', BUCKET]));
const py = (...args) => run('python3', ['/tmp/s3check.py', S3, creds.key, creds.secret, ...args]);
const object = (name) => { try { const o = JSON.parse(py('head', BUCKET, `${FOLDER}/${name}`)); return o.etag ? o : null; } catch { return null; } };
check(creds.key && creds.secret, 'moto is up, with a key and a bucket, checking signatures');

// ------------------------------------------------------------------ the panel
const browser = await chromium.launch();
const admin = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US' });
await admin.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
await logIn(admin);
const csrf = async () => (await admin.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const api = async (method, path, data) => admin.request.fetch(`${BASE}/api${path}`, { method, data, headers: { 'X-CSRF-Token': await csrf() }, timeout: 600000 });
const json = async (res) => res.json().catch(() => ({}));
const page = await admin.newPage();
page.on('dialog', (d) => d.accept());
const consoleErrors = [];
page.on('console', (m) => { if (m.type() === 'error' && !/jobs\/latest/.test(m.location()?.url || '')) consoleErrors.push(m.text()); });
const go = async (path) => { await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle' }); await page.waitForTimeout(400); };
const tab = async (name) => { await page.getByRole('tab', { name }).click(); await page.waitForTimeout(300); };
const notice = async (text) => page.getByText(text, { exact: false }).first().waitFor({ timeout: 120000 }).then(() => true, () => false);
const schedules = async () => json(await api('GET', '/maintenance/backup-schedules'));
const waitJob = async (jobId) => {
  for (let i = 0; i < 300; i++) {
    const job = (await json(await api('GET', '/maintenance/backup-jobs'))).jobs?.find((j) => j.job_id === jobId);
    if (job && ['done', 'error'].includes(job.status)) return job;
    await sleep(1000);
  }
  return null;
};
// One run of the scheduler, as its timer would start it; the schedule's
// last run after it.
const runScheduler = async (id) => {
  run('systemctl', ['start', 'snpanel-backup-scheduler.service']);
  return (await schedules()).find((s) => s.id === id);
};
const nextMinute = async () => { const now = new Date(); await sleep((61 - now.getSeconds()) * 1000); };

let userId = null;
let siteId = null;
let targetId = null;
let sftpTargetId = null;
const made = [];
run('systemctl', ['stop', 'snpanel-backup-scheduler.timer']);
try {
  // ---------------------------------------------------------------- setup
  const old = (await json(await api('GET', '/users?usage=0'))).find((u) => u.username === NAME);
  if (old) await api('DELETE', `/users/${old.id}`);
  run('rm', ['-rf', USER_DIR]);
  for (const t of await json(await api('GET', '/maintenance/s3-targets'))) if (t.name.startsWith('moto')) await api('DELETE', `/maintenance/s3-targets/${t.id}`);
  const user = await api('POST', '/users', { username: NAME, email: `${NAME}@example.com`, password: 's3 check password 1', role: 'end_user', website_limit: 2, storage_limit_mb: 500 });
  userId = (await json(user)).id;
  const site = await json(await api('POST', '/websites', { domain: DOMAIN, app_type: 'static', owner_id: userId }));
  siteId = site.id;
  // 20 MB that gzip cannot shrink: the archive goes up in two parts.
  run('dd', ['if=/dev/urandom', `of=${site.root_path}/noise.bin`, 'bs=1M', 'count=20', 'status=none']);
  run('chown', ['--reference', site.root_path, `${site.root_path}/noise.bin`]);
  check(userId && siteId, `a user with a site holding 20 MB (${DOMAIN})`);

  // ---------------------------------------------------------------- a destination
  await go('/backups');
  await tab('Destinations');
  await page.getByLabel('Name', { exact: true }).fill('moto');
  await page.getByLabel('Endpoint', { exact: true }).fill(S3);
  await page.getByLabel('Region', { exact: true }).fill('us-east-1');
  await page.getByLabel('Bucket', { exact: true }).fill(BUCKET);
  await page.getByLabel('Folder (optional)', { exact: true }).fill(`/${FOLDER}/`);
  await page.getByLabel('Access key', { exact: true }).fill(creds.key);
  await page.getByLabel('Secret key', { exact: true }).fill(creds.secret);
  check(await page.getByText('Plain HTTP sends backups unencrypted').isVisible(), 'plain HTTP is warned about');
  await page.getByLabel('Path-style addressing').check();
  await page.screenshot({ path: `${OUT}/destinations-form-light-en.png`, fullPage: true });
  await page.getByRole('button', { name: 'Add S3 destination' }).click();
  check(await notice('moto accepts backups.'), 'a new destination is tested as it is saved, and passes');
  const listed = (await json(await api('GET', '/maintenance/s3-targets'))).find((t) => t.name === 'moto');
  targetId = listed?.id;
  check(listed && listed.prefix === FOLDER && listed.endpoint === S3 && listed.path_style === true, `stored normalised (${JSON.stringify(listed)})`);
  check(!JSON.stringify(listed).includes(creds.secret) && !('secret_key' in (listed || {})), 'the list holds no secret');
  const dbFile = (readFileSync('/opt/snpanel/backend/.env', 'utf8').match(/^DATABASE_URL=sqlite:\/\/\/?(.*)$/m) || [])[1];
  const stored = run('python3', ['-c', `import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute("select secret_key from s3_backup_targets where id=?", (int(sys.argv[2]),)).fetchone()[0])`, dbFile, String(targetId)]).trim();
  check(stored && !stored.includes(creds.secret) && stored !== creds.secret, `the database holds the secret encrypted (${stored.slice(0, 12)}...)`);
  check(!object('.snpanel-write-test'), 'the test file was removed again');
  await page.screenshot({ path: `${OUT}/destinations-light-en.png`, fullPage: true });

  // A wrong secret: S3's own refusal. A blank one: kept.
  const edit = (secret) => api('PUT', `/maintenance/s3-targets/${targetId}`, { ...listed, name: 'moto', secret_key: secret });
  await edit(`${creds.secret.slice(0, -4)}XXXX`);
  let tested = await api('POST', `/maintenance/s3-targets/${targetId}/test`);
  const refusal = (await json(tested)).detail || '';
  check(tested.status() === 502 && /SignatureDoesNotMatch/.test(refusal), `a wrong secret fails the test with S3's words (${tested.status()} ${refusal})`);
  await edit(creds.secret);
  const renamed = await api('PUT', `/maintenance/s3-targets/${targetId}`, { ...listed, name: 'moto offsite', secret_key: '' });
  tested = await api('POST', `/maintenance/s3-targets/${targetId}/test`);
  check(renamed.status() === 200 && tested.status() === 200, `an edit with the secret left blank keeps it (${renamed.status()}, ${tested.status()})`);
  await api('PUT', `/maintenance/s3-targets/${targetId}`, { ...listed, name: 'moto', secret_key: '' });

  // ---------------------------------------------------------------- a user backup, in parts
  await go('/backups');
  await tab('Backup user');
  await page.getByLabel('User', { exact: true }).selectOption({ label: NAME });
  await page.getByLabel('Destination').selectOption({ label: 'moto' });
  const queued = page.waitForResponse((r) => r.url().endsWith('/api/maintenance/user-backup'));
  await page.getByRole('button', { name: 'Create backup' }).click();
  const job = await waitJob((await (await queued).json()).job_id);
  const archive = job?.backup_file || '';
  const name = archive.split('/').pop();
  check(job?.status === 'done' && job.remote_file === `s3://${BUCKET}/${FOLDER}/${name}`, `a full user backup goes to the bucket (${job?.status} ${job?.remote_file || job?.error})`);
  const up = object(name);
  check(up && /-2"$/.test(up.etag), `in two parts (${up?.size} bytes, ETag ${up?.etag})`);
  py('get', BUCKET, `${FOLDER}/${name}`, '/tmp/s3check-down.tar.gz');
  check(existsSync(archive) && sha('/tmp/s3check-down.tar.gz') === sha(archive), 'byte for byte the archive kept here');

  // ---------------------------------------------------------------- a schedule, by weekday
  await go('/backups');
  await tab('Scheduled backups');
  await page.getByLabel('Users', { exact: true }).selectOption([String(userId)]);
  await page.getByLabel('Runs at (cron)').fill('* * * * *');
  await page.getByLabel('Destination').selectOption({ label: 'moto' });
  await page.getByLabel('Append to the file name').selectOption('weekday');
  const example = await page.locator('#bk-schedule-style-hint code').innerText();
  check(example === `${NAME}-${weekday}.tar.gz`, `the form shows the name it will write (${example})`);
  check(!(await page.getByLabel('Keep').isVisible()), 'and asks for no retention: the names rotate');
  await page.screenshot({ path: `${OUT}/schedule-light-en.png`, fullPage: true });
  await page.getByRole('button', { name: 'Add schedule' }).click();
  await notice('Backup schedule saved.');
  let schedule = (await schedules()).find((s) => s.s3_target_id === targetId);
  made.push(schedule?.id);
  check(schedule?.name_style === 'weekday' && schedule.target_id === null, `saved with its destination and naming (${JSON.stringify(schedule)})`);
  const inUse = await api('DELETE', `/maintenance/s3-targets/${targetId}`);
  check(inUse.status() === 409 && /schedule #\d+ uploads here/.test(await inUse.text()), 'a destination a schedule uses cannot be deleted');

  const before = local();
  schedule = await runScheduler(schedule.id);
  const byDay = `${NAME}-${weekday}.tar.gz`;
  check(schedule.last_status === 'ok' && schedule.last_message.includes(`moto:s3://${BUCKET}/${FOLDER}/${byDay}`), `the scheduler uploads (${schedule.last_status}: ${schedule.last_message})`);
  check(local().includes(byDay) && before.every((f) => local().includes(f)), `kept here as ${byDay}, beside the timestamped one`);
  check(!!object(byDay), 'and in the bucket under the same name');
  check(!local().some((f) => f.includes('.partial')), 'no partial file is left');
  await api('DELETE', `/maintenance/backup-schedules/${schedule.id}`);

  // ---------------------------------------------------------------- by the user alone, replaced
  let res = await api('POST', '/maintenance/backup-schedules', { user_ids: [userId], schedule: '* * * * *', s3_target_id: targetId, name_style: 'none', retention: 1 });
  schedule = await json(res);
  made.push(schedule.id);
  schedule = await runScheduler(schedule.id);
  const plain = `${NAME}.tar.gz`;
  const first = { here: sha(`${USER_DIR}/${plain}`), there: object(plain) };
  await nextMinute();
  schedule = await runScheduler(schedule.id);
  const second = { here: sha(`${USER_DIR}/${plain}`), there: object(plain) };
  check(schedule.last_status === 'ok' && first.here !== second.here && first.there?.etag !== second.there?.etag,
    `the next run replaces the file here and in the bucket (${schedule.last_status}: ${schedule.last_message})`);
  check(local().filter((f) => f.startsWith(`${NAME}.`)).length === 1, 'one file, however many runs');
  check(local().includes(byDay) && local().includes(name), "a retention of one deletes none of the other names' files");
  await api('DELETE', `/maintenance/backup-schedules/${schedule.id}`);

  // ---------------------------------------------------------------- by the date, pruned
  writeFileSync(`${USER_DIR}/${NAME}-2020-01-01.tar.gz`, 'old');
  writeFileSync(`${USER_DIR}/${NAME}-2020-01-02.tar.gz`, 'old');
  res = await api('POST', '/maintenance/backup-schedules', { user_ids: [userId], schedule: '* * * * *', name_style: 'date', retention: 2 });
  schedule = await json(res);
  made.push(schedule.id);
  schedule = await runScheduler(schedule.id);
  const dated = `${NAME}-${today}.tar.gz`;
  check(schedule.last_status === 'ok' && schedule.last_message.includes(`${USER_DIR}/${dated}`), `kept here only when there is no destination (${schedule.last_message})`);
  const after = local();
  check(after.includes(dated) && after.includes(`${NAME}-2020-01-02.tar.gz`) && !after.includes(`${NAME}-2020-01-01.tar.gz`),
    `the dated files are pruned to the retention (${after.join(' ')})`);
  check(after.includes(byDay) && after.includes(plain) && after.includes(name), 'and nothing else is');
  await api('DELETE', `/maintenance/backup-schedules/${schedule.id}`);

  // ---------------------------------------------------------------- SFTP again
  const access = await json(await api('PUT', `/users/${userId}/sftp`, { enabled: true, generate: true }));
  check(!!access.password, 'the user has an SFTP login');
  const sftp = await json(await api('POST', '/maintenance/sftp-targets', { name: 'loopback-check', host: '127.0.0.1', port: 22, username: access.username, password: access.password, remote_path: `/${DOMAIN}/offsite` }));
  sftpTargetId = sftp.id;
  res = await api('POST', '/maintenance/backup-schedules', { user_ids: [userId], schedule: '* * * * *', target_id: sftpTargetId, name_style: 'timestamp', retention: 7 });
  schedule = await json(res);
  made.push(schedule.id);
  schedule = await runScheduler(schedule.id);
  const landed = run('ls', [`/home/${access.username}/${DOMAIN}/offsite`]).trim().split('\n').filter(Boolean);
  check(schedule.last_status === 'ok' && /loopback-check:\/.*\/offsite\/user-s3check-\d+\.tar\.gz/.test(schedule.last_message) && landed.length === 1,
    `the scheduler uploads to an SFTP target again (${schedule.last_status}: ${schedule.last_message})`);
  const uploaded = landed[0] ? `/home/${access.username}/${DOMAIN}/offsite/${landed[0]}` : '';
  check(uploaded && sha(uploaded) === sha(`${USER_DIR}/${landed[0]}`), 'streamed whole: the copy is the archive');
  const pinned = (await json(await api('GET', '/maintenance/sftp-targets'))).find((t) => t.id === sftpTargetId);
  check(!!pinned?.host_key_fingerprint, `and pins the server's host key (${pinned?.host_key_type})`);
  const both = await api('POST', '/maintenance/backup-schedules', { user_ids: [userId], target_id: sftpTargetId, s3_target_id: targetId });
  check(both.status() === 422, 'one destination per schedule');

  // ---------------------------------------------------------------- the pages
  await go('/backups');
  await tab('Scheduled backups');
  await page.screenshot({ path: `${OUT}/schedules-light-en.png`, fullPage: true });
  // A context of its own for each: the admin context's init script puts the
  // theme and the language back on every load.
  for (const [theme, locale] of [['dark', 'en'], ['light', 'vi'], ['dark', 'vi']]) {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
    await context.addInitScript(([t, l]) => { try { localStorage.setItem('snpanel-theme', t); localStorage.setItem('snpanel-locale', l); } catch {} }, [theme, locale]);
    await logIn(context);
    const shot = await context.newPage();
    await shot.goto(`${BASE}/backups`, { waitUntil: 'networkidle' });
    for (const [index, name] of [[2, 'schedules'], [3, 'destinations']]) {
      await shot.locator('.backup-tabs [role=tab]').nth(index).click();
      await shot.waitForTimeout(400);
      await shot.screenshot({ path: `${OUT}/${name}-${theme}-${locale}.png`, fullPage: true });
    }
    await context.close();
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await go('/backups');
  await tab('Scheduled backups');
  const wide = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(wide <= 0, `no sideways scroll on a phone (${wide}px)`);
  await page.screenshot({ path: `${OUT}/schedule-phone.png`, fullPage: true });

  check(consoleErrors.length === 0, `no console errors (${consoleErrors.slice(0, 3).join(' | ')})`);
} finally {
  for (const id of made.filter(Boolean)) await api('DELETE', `/maintenance/backup-schedules/${id}`);
  if (sftpTargetId) await api('DELETE', `/maintenance/sftp-targets/${sftpTargetId}`);
  if (targetId) await api('DELETE', `/maintenance/s3-targets/${targetId}`);
  if (siteId) await api('DELETE', `/websites/${siteId}?delete_files=true`);
  if (userId) await api('DELETE', `/users/${userId}`);
  run('rm', ['-rf', USER_DIR, '/tmp/s3check-down.tar.gz', '/tmp/s3check.py']);
  run('systemctl', ['start', 'snpanel-backup-scheduler.timer']);
  moto.kill();
  await browser.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
