// The malware quarantine end to end on the box, as root - no browser, the
// API the pages call, with the EICAR test file (harmless; every scanner
// flags it):
//
//   - a user of its own with a site holding eicar.php and a clean file;
//   - a scan of the site sets eicar.php aside when it ends: gone from the
//     site, in the quarantine, the job saying so, the clean file untouched;
//   - put back: its owner and its mode again, the job saying "restored";
//   - set aside again by hand; put back and whitelisted;
//   - scanned again: found, but whitelisted - left where it is;
//   - its content changed: set aside again, the whitelist no longer
//     matching;
//   - deleted for good; taken off the whitelist.
//
//     node quarantine-check.mjs          (on the box, as root)
//
// Removes the user, its site and what it put in the quarantine.
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, statSync, writeFileSync, chownSync, chmodSync } from 'node:fs';

const BASE = process.env.PANEL_BASE || 'https://127.0.0.1:2222';
const NAME = 'qcheck';
const DOMAIN = `q${Date.now() % 1000000}.example.com`;
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
    req.setTimeout(1800000, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}
const short = (r) => `${r.status} ${(r.text || '').slice(0, 180)}`;

async function scan(siteId) {
  const started = await api('POST', '/malware/run', { website_id: siteId });
  const id = started.json?.job_id;
  for (let i = 0; id && i < 600; i += 1) {
    const job = (await api('GET', `/malware/jobs/${id}`)).json;
    if (job && !['queued', 'running'].includes(job.status)) return job;
    await sleep(1000);
  }
  return started.json;
}
const threatOf = (job, path) => (job?.threats || []).find((t) => t.path === path);
const quarantined = async () => (await api('GET', '/malware/quarantine')).json?.items || [];

const login = readFileSync('/root/login.txt', 'utf8');
const signedIn = await api('POST', '/auth/login', { username: /^User: (.+)$/m.exec(login)[1].trim(), password: /^Password: (.+)$/m.exec(login)[1].trim() });
check(signedIn.ok, `the administrator signs in (${signedIn.status})`);
let userId = null;
let eicarPath = '';
try {
  const old = ((await api('GET', '/users?usage=0')).json || []).find((u) => u.username === NAME);
  if (old) await api('DELETE', `/users/${old.id}`);
  userId = (await api('POST', '/users', { username: NAME, email: `${NAME}@example.com`, password: `Q-${randomBytes(12).toString('base64url')}`, role: 'end_user', website_limit: 2, storage_limit_mb: 500 })).json?.id;
  const site = (await api('POST', '/websites', { domain: DOMAIN, app_type: 'static', owner_id: userId })).json;
  eicarPath = `${site.root_path}/eicar.php`;
  const cleanPath = `${site.root_path}/about.html`;
  writeFileSync(eicarPath, EICAR);
  writeFileSync(cleanPath, '<p>fine</p>');
  const owner = statSync(site.root_path);
  for (const p of [eicarPath, cleanPath]) chownSync(p, owner.uid, owner.gid);
  chmodSync(eicarPath, 0o640);
  check(userId && existsSync(eicarPath), `a user with a site holding eicar.php (${DOMAIN})`);

  // ---------------------------------------------------------------- a scan sets it aside
  let job = await scan(site.id);
  let threat = threatOf(job, eicarPath);
  check(job?.status === 'infected' && threat, `the scan finds eicar.php (${job?.status} ${job?.message})`);
  check(threat?.state === 'quarantined' && threat?.quarantine_id, `and sets it aside when it ends (${threat?.state} ${threat?.error || ''})`);
  check(job?.quarantined === 1 && job?.infected === 0, `the job counts it quarantined, nothing left in place (${job?.quarantined}/${job?.infected})`);
  check(!existsSync(eicarPath) && existsSync(cleanPath), 'eicar.php is gone from the site, the clean file is not');
  let held = (await quarantined()).find((i) => i.id === threat?.quarantine_id);
  check(held?.path === eicarPath && held?.uid === owner.uid && held?.mode === 0o640 && held?.job === job?.job_id, `the quarantine lists it with its owner, mode and scan (${JSON.stringify(held || {}).slice(0, 160)})`);
  const stored = `/var/lib/snpanel-quarantine/items/${threat?.quarantine_id}/file`;
  check(existsSync(stored) && (statSync(stored).mode & 0o777) === 0o600 && statSync(stored).uid === 0, 'kept root\'s, 0600, in a store only root reads');
  check((statSync('/var/lib/snpanel-quarantine').mode & 0o777) === 0o700, 'the store is 0700');

  // ---------------------------------------------------------------- put back
  let answer = await api('POST', `/malware/quarantine/${threat.quarantine_id}/restore`);
  check(answer.ok && existsSync(eicarPath), `put back (${short(answer)})`);
  const back = statSync(eicarPath);
  check(back.uid === owner.uid && back.gid === owner.gid && (back.mode & 0o777) === 0o640, `with its owner and mode (${back.uid}:${back.gid} ${(back.mode & 0o777).toString(8)})`);
  job = (await api('GET', `/malware/jobs/${job.job_id}`)).json;
  check(threatOf(job, eicarPath)?.state === 'restored' && job.infected === 1, `the job says restored, one in place (${threatOf(job, eicarPath)?.state} ${job.infected})`);

  // ---------------------------------------------------------------- by hand, then put back and whitelisted
  answer = await api('POST', '/malware/threats/quarantine', { job_id: job.job_id, path: eicarPath });
  job = (await api('GET', `/malware/jobs/${job.job_id}`)).json;
  threat = threatOf(job, eicarPath);
  check(answer.ok && threat?.state === 'quarantined' && !existsSync(eicarPath), `set aside again by hand (${short(answer)})`);
  answer = await api('POST', `/malware/quarantine/${threat.quarantine_id}/whitelist`);
  const listed = (await api('GET', '/malware/whitelist')).json?.items || [];
  check(answer.ok && existsSync(eicarPath) && listed.some((e) => e.path === eicarPath), `put back and whitelisted (${short(answer)})`);

  // ---------------------------------------------------------------- scanned again: judged fine
  job = await scan(site.id);
  threat = threatOf(job, eicarPath);
  check(threat?.state === 'whitelisted' && existsSync(eicarPath) && job.infected === 0, `scanned again, it is found but whitelisted and left where it is (${threat?.state} infected=${job?.infected})`);

  // ---------------------------------------------------------------- changed: set aside again
  writeFileSync(eicarPath, `${EICAR}\n`);
  job = await scan(site.id);
  threat = threatOf(job, eicarPath);
  if (threat) {
    check(threat.state === 'quarantined' && !existsSync(eicarPath), `changed, it no longer matches the whitelist and is set aside (${threat.state})`);
  } else {
    console.log(`SKIP  the scanner does not flag the changed file (${job?.status}), so the whitelist's hash cannot be tried here`);
  }

  // ---------------------------------------------------------------- deleted, unlisted
  const id = threat?.quarantine_id || (await quarantined()).find((i) => i.path === eicarPath)?.id;
  if (id) {
    answer = await api('DELETE', `/malware/quarantine/${id}`);
    check(answer.ok && !existsSync(`/var/lib/snpanel-quarantine/items/${id}`) && !(await quarantined()).some((i) => i.id === id), `deleted for good (${short(answer)})`);
  }
  answer = await api('DELETE', '/malware/whitelist', { path: eicarPath });
  check(answer.ok && !((await api('GET', '/malware/whitelist')).json?.items || []).some((e) => e.path === eicarPath), `taken off the whitelist (${short(answer)})`);

  // ---------------------------------------------------------------- refused
  const bogus = await api('POST', '/malware/threats/quarantine', { job_id: '../../etc/x', path: eicarPath });
  check(bogus.status === 404, `a job id that is not one is refused (${bogus.status})`);
  const wrong = await api('POST', '/malware/quarantine/0123456789abcdef0123456789abcdef/restore');
  check(wrong.status === 404, `an id not in the quarantine is refused (${wrong.status})`);
} finally {
  for (const item of await quarantined()) if (item.path?.startsWith(`/home/${NAME}/`)) await api('DELETE', `/malware/quarantine/${item.id}`);
  if (eicarPath) await api('DELETE', '/malware/whitelist', { path: eicarPath });
  if (userId) await api('DELETE', `/users/${userId}`);
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
