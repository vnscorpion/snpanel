// On a fresh test machine, what restore-ui.mjs needs: an end user `demo`
// with a static website and one backup (restore-ui.mjs makes the second).
//
//     node restore-prep.mjs          (on the box, as root)
//
// For a machine that is thrown away after its checks: nothing is removed.
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

const ACCOUNT = 'demo';
const PASSWORD = `D-${randomBytes(15).toString('base64url')}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function session(base) {
  const jar = new Map();
  return async function api(method, path, body) {
    const headers = {};
    let payload;
    if (path === '/auth/login') { headers['Content-Type'] = 'application/x-www-form-urlencoded'; payload = new URLSearchParams(body).toString(); }
    else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
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
      req.on('error', reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  };
}
const LOCAL = 'https://127.0.0.1:2222';
const admin = session(LOCAL);
const login = readFileSync('/root/login.txt', 'utf8');
await admin('POST', '/auth/login', { username: /^User: (.+)$/m.exec(login)[1].trim(), password: /^Password: (.+)$/m.exec(login)[1].trim() });
const listed = (await admin('GET', '/users?usage=0')).json;
let user = (listed?.items || listed || []).find((u) => u.username === ACCOUNT);
if (!user) {
  user = (await admin('POST', '/users', { username: ACCOUNT, email: `${ACCOUNT}@example.invalid`, password: PASSWORD, role: 'end_user', website_limit: 2, storage_limit_mb: 500 })).json;
  const owner = session(LOCAL);
  await owner('POST', '/auth/login', { username: ACCOUNT, password: PASSWORD });
  const site = await owner('POST', '/websites', { domain: 'demo-site.example.com', app_type: 'static' });
  console.log(`user ${ACCOUNT}: ${user?.id}, site: ${site.status}`);
}
const started = await admin('POST', '/maintenance/user-backup', { user_id: user.id });
let job = null;
for (let i = 0; i < 200 && !['done', 'error'].includes(job?.status); i += 1) {
  await sleep(1500);
  job = (await admin('GET', `/maintenance/backup-jobs/${started.json?.job_id}`)).json;
}
console.log(`backup: ${job?.status} ${job?.backup_file || job?.error || started.text.slice(0, 200)}`);
process.exit(job?.status === 'done' ? 0 : 1);
