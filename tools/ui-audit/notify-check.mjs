// The Notifications addon, end to end on the box, as root - no browser, the
// API the page calls, an SMTP server and a Telegram Bot API of this script's
// own:
//
//   - an SMTP relay on 127.0.0.1:2525 that takes AUTH PLAIN, and a Telegram
//     API on 127.0.0.1:8099 the panel is pointed at for the run
//     (SNPANEL_TELEGRAM_API_BASE, in a drop-in that is removed again);
//   - the SMTP server saved - its password never in an answer - a test mail
//     through it, signed in with the saved password; no password in the clear
//     to a server that is not this machine;
//   - a Telegram bot saved, checked with getMe; the administrator's chat
//     linked by /start <code>;
//   - a customer of its own: a sign-in from a new address, a password its
//     administrator changed, a scheduled backup that fails, malware on its
//     website - each told to the customer (in English, its choice) and, where
//     it is the server's business, to the administrator (by mail and on
//     Telegram, in Vietnamese);
//   - a service stopped, seen twice, told once, and told again when it runs;
//   - an event turned off is not told; the log shows what went.
//
//     node notify-check.mjs          (on the box, as root)
//
// Removes the customer, its site, the schedule and destination, the channels
// and the drop-in. The addon is left installed, with no way of sending set.
import https from 'node:https';
import http from 'node:http';
import net from 'node:net';
import { execFile, execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chownSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';

const NAME = 'notifycheck';
const DOMAIN = `ntf${Date.now() % 1000000}.example.com`;
const RELAY_PASSWORD = `relay-${randomBytes(9).toString('base64url')}`;
const BOT_TOKEN = `123456789:${randomBytes(27).toString('base64url')}`;
const DROPIN_DIR = '/etc/systemd/system/snpanel-api.service.d';
const DROPIN = `${DROPIN_DIR}/zz-notify-check.conf`;
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };
const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return String(e.stdout || '') + String(e.stderr || ''); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const runAsync = (cmd, args) => new Promise((resolve) => execFile(cmd, args, { encoding: 'utf8' }, (e, out, err) => resolve(String(out || '') + String(err || ''))));
async function until(test, seconds = 30) {
  for (let i = 0; i < seconds * 4; i += 1) {
    const got = await test();
    if (got) return got;
    await sleep(250);
  }
  return null;
}

// ---------------------------------------------------------------- the SMTP relay
const mails = [];
const smtp = net.createServer((socket) => {
  let buffer = '';
  let data = null;
  const mail = { from: '', to: [], auth: null, raw: '' };
  const say = (line) => socket.write(`${line}\r\n`);
  say('220 relay.test ESMTP');
  socket.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    let at;
    while ((at = buffer.indexOf('\r\n')) >= 0) {
      const line = buffer.slice(0, at);
      buffer = buffer.slice(at + 2);
      if (data !== null) {
        if (line === '.') {
          mail.raw = data;
          mails.push({ ...mail, to: [...mail.to] });
          data = null;
          say('250 2.0.0 queued');
        } else {
          data += `${line.startsWith('..') ? line.slice(1) : line}\r\n`;
        }
        continue;
      }
      const verb = line.split(/[ :]/)[0].toUpperCase();
      if (verb === 'EHLO') { socket.write('250-relay.test\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n'); }
      else if (verb === 'AUTH') {
        const [, user, pass] = Buffer.from(line.split(' ')[2] || '', 'base64').toString('utf8').split('\0');
        mail.auth = { user, pass };
        say(pass === RELAY_PASSWORD ? '235 2.7.0 ok' : '535 5.7.8 no');
      } else if (verb === 'MAIL') { mail.from = line.slice(10).replace(/[<>]/g, ''); say('250 ok'); }
      else if (verb === 'RCPT') { mail.to.push(line.slice(8).replace(/[<>]/g, '')); say('250 ok'); }
      else if (verb === 'DATA') { data = ''; say('354 go on'); }
      else if (verb === 'QUIT') { say('221 bye'); socket.end(); }
      else say('250 ok');
    }
  });
  socket.on('error', () => {});
});
await new Promise((r) => smtp.listen(2525, '127.0.0.1', r));

// RFC 2047 words and the base64 parts, read back.
function decodeWords(value) {
  return value.replace(/\r\n /g, '').replace(/=\?utf-8\?b\?([^?]+)\?=/gi, (m, b64) => Buffer.from(b64, 'base64').toString('utf8'));
}
function read(mail) {
  const [head, ...rest] = mail.raw.split('\r\n\r\n');
  const header = (name) => decodeWords(((new RegExp(`^${name}: ((?:.*)(?:\\r\\n .*)*)`, 'mi').exec(head) || [])[1]) || '');
  const body = rest.join('\r\n\r\n');
  const plain = /Content-Type: text\/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n([A-Za-z0-9+/=\r\n]+)/.exec(body);
  return { to: mail.to, subject: header('Subject'), from: header('From'), text: plain ? Buffer.from(plain[1].replace(/\r\n/g, ''), 'base64').toString('utf8') : '' };
}
const mailTo = (address, subject) => until(() => mails.map(read).find((m) => m.to.includes(address) && subject.test(m.subject)), 90);

// ---------------------------------------------------------------- the Telegram API
const sent = [];
let updates = [];
let nextUpdate = 100;
const bot = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const answer = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    const m = /^\/bot([^/]+)\/(\w+)$/.exec(req.url);
    if (!m || m[1] !== BOT_TOKEN) return answer(404, { ok: false, error_code: 404, description: 'Not Found' });
    const payload = body ? JSON.parse(body) : {};
    if (m[2] === 'getMe') return answer(200, { ok: true, result: { id: 123456789, is_bot: true, username: 'snpanel_check_bot' } });
    if (m[2] === 'sendMessage') {
      if (String(payload.chat_id) === '404') return answer(400, { ok: false, error_code: 400, description: 'Bad Request: chat not found' });
      sent.push({ chat: String(payload.chat_id), text: payload.text, mode: payload.parse_mode });
      return answer(200, { ok: true, result: { message_id: sent.length } });
    }
    if (m[2] === 'getUpdates') {
      updates = updates.filter((u) => u.update_id >= (payload.offset || 0));
      return answer(200, { ok: true, result: updates });
    }
    return answer(400, { ok: false, description: 'unknown method' });
  });
});
await new Promise((r) => bot.listen(8099, '127.0.0.1', r));
const told = (chat, text) => until(() => sent.find((s) => s.chat === chat && text.test(s.text)), 90);

// ---------------------------------------------------------------- the panel, pointed at them
mkdirSync(DROPIN_DIR, { recursive: true });
writeFileSync(DROPIN, '[Service]\nEnvironment=SNPANEL_TELEGRAM_API_BASE=http://127.0.0.1:8099\n');
run('systemctl', ['daemon-reload']);
run('systemctl', ['restart', 'snpanel-api']);

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
    headers['User-Agent'] = 'notify-check';
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
const short = (r) => `${r.status} ${(r.text || '').slice(0, 160)}`;
const LOCAL = 'https://127.0.0.1:2222';
const OWN_IP = run('hostname', ['-I']).trim().split(/\s+/)[0];
const OUTSIDE = `https://${OWN_IP}:2222`;
await until(async () => { try { return (await session(LOCAL)('GET', '/health')).ok; } catch { return false; } }, 60);

const admin = session(LOCAL);
const login = readFileSync('/root/login.txt', 'utf8');
const adminName = /^User: (.+)$/m.exec(login)[1].trim();
check((await admin('POST', '/auth/login', { username: adminName, password: /^Password: (.+)$/m.exec(login)[1].trim() })).ok, 'the administrator signs in');
const adminUser = ((await admin('GET', '/users?usage=0')).json || []).find((u) => u.username === adminName);

let userId = null;
let siteId = null;
let targetId = null;
let scheduleId = null;
try {
  const addons = (await admin('GET', '/addons')).json;
  if (!addons.items.find((a) => a.slug === 'notifications')?.installed) await admin('POST', '/addons/notifications/install');
  // Only what this run sends is judged: the log keeps earlier runs' too.
  const logStart = Math.max(0, ...(((await admin('GET', '/notifications/log')).json?.items) || []).map((r) => r.id));
  let view = (await admin('GET', '/notifications')).json;
  check(view?.installed && view.admin && view.events.length === 15, `installed, with 15 events for an administrator (${view?.events?.length})`);

  // ---------------------------------------------------------------- mail
  const refused = await admin('PUT', '/notifications/smtp', { host: 'smtp.example.com', port: 25, security: 'none', username: 'x', password: 'y', from_address: 'panel@snpanel.test' });
  check(refused.status === 400 && /clear/.test(refused.text), `no password in the clear to another machine (${short(refused)})`);
  let answer = await admin('PUT', '/notifications/smtp', { host: '127.0.0.1', port: 2525, security: 'none', username: 'relayuser', password: RELAY_PASSWORD, from_address: 'panel@snpanel.test', from_name: 'SNPanel check' });
  check(answer.ok && answer.json.smtp.password_set && !answer.text.includes(RELAY_PASSWORD), `the SMTP server is saved; its password is never sent back (${answer.status})`);
  const stored = readFileSync('/var/lib/snpanel/notifications.json', 'utf8');
  check(!stored.includes(RELAY_PASSWORD) && /"password": "fernet:/.test(stored) && (statSync('/var/lib/snpanel/notifications.json').mode & 0o777) === 0o600,
    'on disk the password is encrypted, in a 0600 file');
  answer = await admin('POST', '/notifications/test', { channel: 'email', to: 'ops@snpanel.test' });
  const testMail = await mailTo('ops@snpanel.test', /Tin nhắn thử từ panel/);
  check(answer.ok && testMail && testMail.from === '"SNPanel check" <panel@snpanel.test>' && mails.at(-1).auth?.pass === RELAY_PASSWORD,
    `a test mail goes out, signed in with the saved password, in Vietnamese by default (${short(answer)})`);
  check(/Nếu bạn đọc được tin này/.test(testMail?.text || ''), 'its plain part reads in Vietnamese too');

  // ---------------------------------------------------------------- Telegram
  answer = await admin('PUT', '/notifications/telegram', { token: 'not-a-token' });
  check(answer.status === 400, `a token of the wrong shape is refused (${short(answer)})`);
  answer = await admin('PUT', '/notifications/telegram', { token: BOT_TOKEN });
  check(answer.ok && answer.json.channels.telegram.bot === 'snpanel_check_bot' && !answer.text.includes(BOT_TOKEN), `the bot is saved as getMe names it, the token never sent back (${short(answer)})`);
  const link = (await admin('POST', '/notifications/telegram/link')).json;
  check(link?.url === `https://t.me/snpanel_check_bot?start=${link?.code}`, `a link to the bot with a code (${link?.url})`);
  updates.push({ update_id: nextUpdate++, message: { message_id: 1, text: `/start ${link.code}`, chat: { id: 777001, type: 'private' }, from: { id: 777001, username: 'ops_admin', first_name: 'Ops' } } });
  answer = await admin('POST', '/notifications/telegram/link/check');
  check(answer.json?.linked && answer.json?.name === '@ops_admin', `pressing Start links the chat (${short(answer)})`);
  check(await told('777001', /Đã liên kết/), 'and the bot says so in it');
  answer = await admin('POST', '/notifications/telegram/link/check');
  check(answer.status === 409, 'a code is used once');
  await sleep(5500);
  answer = await admin('POST', '/notifications/test', { channel: 'telegram' });
  check(answer.ok && await told('777001', /Tin nhắn thử từ panel/), `a test message reaches the chat (${short(answer)})`);

  // ---------------------------------------------------------------- a customer of its own
  const old = ((await admin('GET', '/users?usage=0')).json || []).find((u) => u.username === NAME);
  if (old) await admin('DELETE', `/users/${old.id}`);
  const first = `N1-${randomBytes(12).toString('base64url')}`;
  userId = (await admin('POST', '/users', { username: NAME, email: `${NAME}@snpanel.test`, password: first, role: 'end_user', website_limit: 2, storage_limit_mb: 500 })).json?.id;
  const customer = session(LOCAL);
  check((await customer('POST', '/auth/login', { username: NAME, password: first })).ok, 'the customer signs in - the first address on record, told to nobody');
  const mine = (await customer('GET', '/notifications')).json;
  check(mine && !mine.admin && mine.events.length === 7 && !('smtp' in mine), `a customer is offered its own 7 events, and nothing of the server's (${mine?.events?.length})`);
  answer = await customer('PUT', '/notifications/me', { language: 'en', events: { server_malware: true } });
  check(answer.status === 403, 'a customer cannot ask for the server\'s events');
  answer = await customer('PUT', '/notifications/me', { language: 'en' });
  check(answer.ok && answer.json.me.language === 'en', 'the customer chooses English');
  await sleep(1500);
  check(!mails.some((m) => m.to.includes(`${NAME}@snpanel.test`)), 'nothing told for the first sign-in');

  const outside = session(OUTSIDE);
  check((await outside('POST', '/auth/login', { username: NAME, password: first })).ok, `the customer signs in again from ${OWN_IP}`);
  let mail = await mailTo(`${NAME}@snpanel.test`, /^A new sign-in to your account$/);
  check(mail && mail.text.includes(`From ${OWN_IP}`) && mail.text.includes('notify-check'), `a sign-in from a new address is told, in English, with the address and browser (${mail?.subject})`);

  const second = `N2-${randomBytes(12).toString('base64url')}`;
  answer = await admin('POST', `/users/${userId}/password`, { password: second });
  mail = await mailTo(`${NAME}@snpanel.test`, /^Your panel password was changed$/);
  check(answer.ok && mail?.text.includes(`By the administrator ${adminName}.`), `a password its administrator changed is told, and by whom (${short(answer)})`);

  // ---------------------------------------------------------------- a backup that fails
  targetId = (await admin('POST', '/maintenance/sftp-targets', { name: 'notify-check', host: '127.0.0.1', port: 1, username: 'nobody', password: 'x', private_key: null, remote_path: '/tmp/notify-check' })).json?.id;
  scheduleId = (await admin('POST', '/maintenance/backup-schedules', { user_ids: [userId], schedule: '0 4 * * *', target_id: targetId, name_style: 'timestamp', retention: 1 })).json?.id;
  answer = await admin('POST', `/maintenance/backup-schedules/${scheduleId}/run`);
  check(answer.ok, `a schedule whose destination cannot be reached is run (${short(answer)})`);
  mail = await mailTo(`${NAME}@snpanel.test`, /^Your account's backup failed$/);
  check(mail && /Reason: /.test(mail.text), `the customer is told its backup failed, and why (${mail?.text?.split('\n')[3] || ''})`);
  check(await told('777001', new RegExp(`Lịch sao lưu bị lỗi: #${scheduleId}`)), 'the administrator is told on Telegram, in Vietnamese');
  check(await mailTo(adminUser.email, new RegExp(`^Lịch sao lưu bị lỗi: #${scheduleId}`)), 'and by mail');

  // ---------------------------------------------------------------- malware on its website
  const site = (await admin('POST', '/websites', { domain: DOMAIN, app_type: 'static', owner_id: userId })).json;
  siteId = site?.id;
  const eicar = `${site.root_path}/eicar.php`;
  writeFileSync(eicar, EICAR);
  const owner = statSync(site.root_path);
  chownSync(eicar, owner.uid, owner.gid);
  const started = await admin('POST', '/malware/run', { website_id: siteId });
  const job = await until(async () => {
    const j = (await admin('GET', `/malware/jobs/${started.json?.job_id}`)).json;
    return j && !['queued', 'running'].includes(j.status) ? j : null;
  }, 600);
  check(job?.status === 'infected' && job?.quarantined === 1, `a scan finds eicar.php and sets it aside (${job?.status} q=${job?.quarantined})`);
  mail = await mailTo(`${NAME}@snpanel.test`, new RegExp(`^Malware found on ${DOMAIN.replace(/\./g, '\\.')}$`));
  check(mail && mail.text.includes('1 moved to quarantine') && mail.text.includes('eicar.php'), 'its owner is told what was found and set aside');
  check(await told('777001', new RegExp(`Phát hiện mã độc trên ${DOMAIN.replace(/\./g, '\\.')}`)), 'and the administrator, on Telegram');

  // ---------------------------------------------------------------- an event turned off
  // The password its administrator changed ended the customer's sessions.
  check((await customer('POST', '/auth/login', { username: NAME, password: second })).ok, 'the customer signs in with the new password');
  answer = await customer('PUT', '/notifications/me', { events: { security: false } });
  check(answer.ok && answer.json.me.events.security === false, 'the customer turns "changes to how you sign in" off');
  const before = mails.length;
  const third = `N3-${randomBytes(12).toString('base64url')}`;
  await admin('POST', `/users/${userId}/password`, { password: third });
  await sleep(4000);
  check(!mails.slice(before).some((m) => m.to.includes(`${NAME}@snpanel.test`)), 'and is not told the next time');

  // ---------------------------------------------------------------- a service that stops
  // Not execFileSync: it would stop this script's relay and Telegram API
  // from answering the very messages the checks send.
  const checks = () => runAsync('systemd-run', ['--quiet', '--pipe', '--wait', '--uid=snpanel', '--gid=snpanel',
    '-p', 'EnvironmentFile=/opt/snpanel/backend/.env', '-p', 'Environment=HOME=/opt/snpanel', '-p', 'Environment=SNPANEL_USE_HELPER=true',
    '-p', 'Environment=SNPANEL_TELEGRAM_API_BASE=http://127.0.0.1:8099', '-p', 'WorkingDirectory=/opt/snpanel/backend',
    '/usr/local/bin/snpanel-api-rust', '--run-notification-checks', '--env', '/opt/snpanel/backend/.env']);
  const redis = run('systemctl', ['list-units', '--type=service', '--no-legend', 'redis*']).split(/\s+/).find((w) => w.startsWith('redis') && w.endsWith('.service'))?.replace('.service', '');
  check(!!redis, `the machine has a Redis service to stop (${redis})`);
  await checks();
  run('systemctl', ['stop', redis]);
  const firstLook = await checks();
  const beforeStop = sent.length;
  await sleep(1000);
  check(/checks ran/.test(firstLook) && !sent.slice(beforeStop).some((s) => /đã dừng/.test(s.text)), 'stopped once: not told yet - it may be a restart');
  await checks();
  check(await told('777001', new RegExp(`Dịch vụ đã dừng: ${redis}`)), 'stopped at the second look: told');
  const tally = sent.filter((s) => /đã dừng/.test(s.text)).length;
  await checks();
  await sleep(1000);
  check(sent.filter((s) => /đã dừng/.test(s.text)).length === tally, 'and told once');
  run('systemctl', ['start', redis]);
  await checks();
  check(await told('777001', new RegExp(`Dịch vụ đã chạy lại: ${redis}`)), 'running again: told');

  // ---------------------------------------------------------------- the log
  const log = ((await admin('GET', '/notifications/log')).json?.items || []).filter((r) => r.id > logStart);
  const events = new Set(log.map((r) => r.event));
  for (const e of ['test', 'sign_in', 'security', 'backup_failed', 'server_backup_failed', 'malware', 'server_malware', 'service_down']) {
    check(events.has(e), `the log has ${e}`);
  }
  const unsent = log.filter((r) => r.status !== 'sent');
  check(unsent.length === 0 && log.every((r) => !r.target.includes(`${NAME}@`)),
    `every one of them sent, the addresses masked${unsent.length ? `: ${JSON.stringify(unsent.map((r) => [r.event, r.channel, r.target, r.detail]))}` : ''}`);
  await customer('POST', '/auth/login', { username: NAME, password: third });
  answer = await customer('GET', '/notifications/log');
  check(answer.status === 403, 'a customer does not read the log');
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.stack || err.message}`);
} finally {
  if (scheduleId) await admin('DELETE', `/maintenance/backup-schedules/${scheduleId}`);
  if (targetId) await admin('DELETE', `/maintenance/sftp-targets/${targetId}`);
  if (siteId) await admin('DELETE', `/websites/${siteId}`);
  if (userId) await admin('DELETE', `/users/${userId}`);
  await admin('DELETE', '/notifications/telegram/link');
  await admin('DELETE', '/notifications/smtp');
  await admin('DELETE', '/notifications/telegram');
  rmSync(DROPIN, { force: true });
  run('systemctl', ['daemon-reload']);
  run('systemctl', ['restart', 'snpanel-api']);
  smtp.close();
  bot.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
