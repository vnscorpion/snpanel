// The Notifications addon, end to end on the box, as root - no browser, the
// API the page calls, an SMTP server and a Telegram Bot API of this script's
// own:
//
//   - an SMTP relay on 127.0.0.1:2525 that takes AUTH PLAIN, and the Telegram
//     API of telegram-mock.mjs on 127.0.0.1:8099, which the panel is pointed
//     at for the run (a drop-in that is removed again);
//   - everything is the administrators': a customer is refused the page, the
//     settings, the test and the log;
//   - the SMTP server saved - its password never in an answer, encrypted on
//     disk - and a test to the administrators' own addresses, then to the
//     addresses given; no password in the clear to another machine;
//   - a Telegram bot and its chat: the chats that wrote to the bot found,
//     a chat Telegram does not know refused in words, a test message sent
//     before anything is saved, a blank token keeping the saved one; a bot
//     saved before there was a chat sends nothing to Telegram;
//   - a second administrator made by the run: told as new, its sign-in from
//     a new address told, its password changed told and by whom;
//   - a customer: its sign-ins and password changes told to nobody; its
//     scheduled backup that fails (in English, chosen) and malware on its
//     website told to the administrators - never to the customer;
//   - an event turned off is not told; a service stopped, seen twice, is
//     told once, and again when it runs; the log shows what went.
//
//     node notify-check.mjs          (on the box, as root, telegram-mock.mjs beside it)
//
// Removes the accounts, the site, the schedule and destination, the channels
// and the drop-in, and puts what is sent back to the defaults. The addon is
// left installed, with no way of sending set.
import https from 'node:https';
import net from 'node:net';
import { execFile, execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chownSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { BOT, GROUP, PERSON, pointPanel, startTelegramMock } from './telegram-mock.mjs';

const NAME = 'notifycheck';
const ADMIN2 = 'notifyadmin';
const DOMAIN = `ntf${Date.now() % 1000000}.example.com`;
const RELAY_PASSWORD = `relay-${randomBytes(9).toString('base64url')}`;
const BOT_TOKEN = `123456789:${randomBytes(27).toString('base64url')}`;
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
const CHANNELS = '/var/lib/snpanel/notifications.json';
const OPS = 'ops@snpanel.test';
const ONCALL = 'oncall@snpanel.test';
const PERSON_CHAT = String(PERSON.id);
const GROUP_CHAT = String(GROUP.id);

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
const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

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
          mail.to = [];
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
const mailTo = (address, subject, since = 0) => until(() => mails.slice(since).map(read).find((m) => m.to.includes(address) && subject.test(m.subject)), 90);

// ---------------------------------------------------------------- the Telegram API
const telegram = startTelegramMock();
await telegram.listening;
const { sent } = telegram;
const told = (chat, text, since = 0) => until(() => sent.slice(since).find((s) => s.chat === chat && text.test(s.text)), 90);

// ---------------------------------------------------------------- the panel, pointed at it
pointPanel(true);

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
const users = async () => (await admin('GET', '/users?usage=0')).json || [];
const adminUser = (await users()).find((u) => u.username === adminName);
const DEFAULTS = {};

let userId = null;
let admin2Id = null;
let siteId = null;
let targetId = null;
let scheduleId = null;
try {
  const addons = (await admin('GET', '/addons')).json;
  if (!addons.items.find((a) => a.slug === 'notifications')?.installed) await admin('POST', '/addons/notifications/install');
  await admin('DELETE', '/notifications/smtp');
  await admin('DELETE', '/notifications/telegram');
  for (const old of (await users()).filter((u) => [NAME, ADMIN2].includes(u.username))) await admin('DELETE', `/users/${old.id}`);
  // Only what this run sends is judged: the log keeps earlier runs' too.
  const logStart = Math.max(0, ...(((await admin('GET', '/notifications/log')).json?.items) || []).map((r) => r.id));
  let view = (await admin('GET', '/notifications')).json;
  for (const e of view?.events || []) DEFAULTS[e.key] = e.default;
  await admin('PUT', '/notifications/settings', { language: 'vi', events: DEFAULTS });
  view = (await admin('GET', '/notifications')).json;
  const groups = [...new Set((view?.events || []).map((e) => e.group))];
  check(view?.installed && !view.ready && view.events.length === 10 && groups.join() === 'accounts,server,admins',
    `installed, nothing to send with yet; 10 events in 3 groups (${view?.events?.length}: ${groups.join()})`);

  // ---------------------------------------------------------------- a customer is kept out
  const first = `N1-${randomBytes(12).toString('base64url')}`;
  userId = (await admin('POST', '/users', { username: NAME, email: `${NAME}@snpanel.test`, password: first, role: 'end_user', website_limit: 2, storage_limit_mb: 500 })).json?.id;
  const customer = session(LOCAL);
  check((await customer('POST', '/auth/login', { username: NAME, password: first })).ok, 'a customer signs in');
  const refusedTo = [];
  for (const [method, path, body] of [['GET', '/notifications'], ['PUT', '/notifications/settings', { language: 'en' }],
    ['POST', '/notifications/test', { channel: 'email' }], ['GET', '/notifications/log'], ['PUT', '/notifications/smtp', {}],
    ['POST', '/notifications/telegram/chats', {}], ['PUT', '/notifications/me', {}]]) {
    const r = await customer(method, path, body);
    if (r.status !== 403 && !(path === '/notifications/me' && [404, 405].includes(r.status))) refusedTo.push(`${method} ${path}: ${r.status}`);
  }
  check(refusedTo.length === 0, `the customer is refused all of it - and the old per-account settings are gone${refusedTo.length ? `: ${refusedTo.join('; ')}` : ''}`);

  // ---------------------------------------------------------------- mail
  let answer = await admin('PUT', '/notifications/smtp', { host: 'smtp.example.com', port: 25, security: 'none', username: 'x', password: 'y', from_address: 'panel@snpanel.test' });
  check(answer.status === 400 && /clear/.test(answer.text), `no password in the clear to another machine (${short(answer)})`);
  answer = await admin('PUT', '/notifications/smtp', { host: '127.0.0.1', port: 2525, security: 'none', username: 'relayuser', password: RELAY_PASSWORD, from_address: 'panel@snpanel.test', from_name: 'SNPanel check' });
  check(answer.ok && answer.json.email.smtp.password_set && !answer.text.includes(RELAY_PASSWORD) && answer.json.ready,
    `the SMTP server is saved; its password is never sent back (${answer.status})`);
  const administrators = answer.json?.email?.administrators || [];
  check(administrators.includes(adminUser.email) && answer.json.email.to.length === 0,
    `with no address given, mail goes to the administrators' own: ${administrators.join(', ')}`);
  const stored = readFileSync(CHANNELS, 'utf8');
  check(!stored.includes(RELAY_PASSWORD) && /"password": "fernet:/.test(stored) && (statSync(CHANNELS).mode & 0o777) === 0o600,
    'on disk the password is encrypted, in a 0600 file');
  let since = mails.length;
  answer = await admin('POST', '/notifications/test', { channel: 'email' });
  const testMail = await mailTo(adminUser.email, /Tin nhắn thử từ panel/, since);
  check(answer.ok && testMail && testMail.from === '"SNPanel check" <panel@snpanel.test>' && mails.at(-1).auth?.pass === RELAY_PASSWORD,
    `a test goes to the administrators' addresses, signed in with the saved password, in Vietnamese (${short(answer)})`);
  check(/Gửi tới quản trị viên của/.test(testMail?.text || ''), 'its plain part says who it is for, in Vietnamese');
  answer = await admin('PUT', '/notifications/smtp', { host: '127.0.0.1', port: 2525, security: 'none', username: 'relayuser', password: '', from_address: 'panel@snpanel.test', from_name: 'SNPanel check', to: 'nobody' });
  check(answer.status === 400 && /nobody is not an e-mail address/.test(answer.text), `an address that is not one is refused (${short(answer)})`);
  answer = await admin('PUT', '/notifications/smtp', { host: '127.0.0.1', port: 2525, security: 'none', username: 'relayuser', password: '', from_address: 'panel@snpanel.test', from_name: 'SNPanel check', to: `${OPS}, ${ONCALL}; ${OPS.toUpperCase()}` });
  check(answer.ok && answer.json.email.to.join() === `${OPS},${ONCALL}` && answer.json.email.smtp.password_set,
    `the addresses to send to are saved, each once; a blank password keeps the saved one (${answer.json?.email?.to})`);
  await sleep(5500);
  since = mails.length;
  answer = await admin('POST', '/notifications/test', { channel: 'email' });
  check(answer.ok && await mailTo(OPS, /Tin nhắn thử/, since) && await mailTo(ONCALL, /Tin nhắn thử/, since)
    && !mails.slice(since).some((m) => m.to.includes(adminUser.email)), `now a test goes to each of them, not the administrators' own (${answer.json?.to})`);

  // ---------------------------------------------------------------- Telegram
  answer = await admin('PUT', '/notifications/telegram', { token: 'not-a-token', chat_id: GROUP_CHAT });
  check(answer.status === 400 && /not a bot token/.test(answer.text), `a token of the wrong shape is refused (${short(answer)})`);
  answer = await admin('PUT', '/notifications/telegram', { token: BOT_TOKEN, chat_id: '' });
  check(answer.status === 400 && /Enter the chat ID/.test(answer.text), `a bot with no chat is not saved (${short(answer)})`);
  answer = await admin('POST', '/notifications/telegram/chats', { token: BOT_TOKEN });
  const found = answer.json?.chats || [];
  check(answer.ok && answer.json.bot === BOT && found.map((c) => `${c.id}|${c.kind}|${c.name}`).join() === `${GROUP_CHAT}|supergroup|Ops team,${PERSON_CHAT}|private|Ops (@ops_admin)`,
    `Find chat ID lists the group the bot was added to and the person who wrote to it, newest first (${short(answer)})`);
  answer = await admin('POST', '/notifications/telegram/chats', { token: BOT_TOKEN });
  check(answer.ok && answer.json.chats.length === 2, 'and looking again finds them again: nothing was marked read');
  answer = await admin('PUT', '/notifications/telegram', { token: BOT_TOKEN, chat_id: '404' });
  check(answer.status === 502 && /does not know that chat for this bot/.test(answer.text) && !(await admin('GET', '/notifications')).json.telegram.bot,
    `a chat Telegram does not know is refused in words, and nothing is saved (${short(answer)})`);
  let sentBefore = sent.length;
  answer = await admin('PUT', '/notifications/telegram', { token: BOT_TOKEN, chat_id: GROUP_CHAT });
  check(answer.ok && answer.json.telegram.ready && answer.json.telegram.bot === BOT && answer.json.telegram.chat_name === 'Ops team' && !answer.text.includes(BOT_TOKEN),
    `the bot and the group are saved, the token never sent back (${short(answer)})`);
  check(await told(GROUP_CHAT, /^<b>Tin nhắn thử từ panel<\/b>/, sentBefore), 'a test message reached the group before it was saved');
  check(!readFileSync(CHANNELS, 'utf8').includes(BOT_TOKEN), 'the token is encrypted on disk');
  answer = await admin('PUT', '/notifications/telegram', { token: '', chat_id: PERSON_CHAT });
  check(answer.ok && answer.json.telegram.chat_id === PERSON_CHAT && answer.json.telegram.chat_name === 'Ops (@ops_admin)',
    `a blank token keeps the saved bot; the chat is now the person's (${answer.json?.telegram?.chat_name})`);
  // A bot saved before there was a chat ID: nowhere to send on Telegram.
  const saved = JSON.parse(readFileSync(CHANNELS, 'utf8'));
  const withChat = JSON.stringify(saved, null, 2);
  delete saved.telegram.chat_id;
  delete saved.telegram.chat_name;
  writeFileSync(CHANNELS, JSON.stringify(saved, null, 2));
  view = (await admin('GET', '/notifications')).json;
  check(view.telegram.bot === BOT && !view.telegram.ready && view.telegram.chat_id === '',
    'a bot saved without a chat, as the first version saved it, is shown as not ready');
  sentBefore = sent.length;
  await sleep(5500);
  answer = await admin('POST', '/notifications/test', { channel: 'telegram' });
  check(answer.status === 409 && sent.length === sentBefore, `and nothing goes to Telegram (${short(answer)})`);
  writeFileSync(CHANNELS, withChat);
  await sleep(5500);
  answer = await admin('POST', '/notifications/test', { channel: 'telegram' });
  check(answer.ok && await told(PERSON_CHAT, /Tin nhắn thử từ panel/, sentBefore), `with its chat back, a test reaches it (${short(answer)})`);

  // ---------------------------------------------------------------- a second administrator
  const a2first = `A1-${randomBytes(12).toString('base64url')}`;
  sentBefore = sent.length;
  since = mails.length;
  admin2Id = (await admin('POST', '/users', { username: ADMIN2, email: `${ADMIN2}@snpanel.test`, password: a2first, role: 'admin', website_limit: 0, storage_limit_mb: 0 })).json?.id;
  let message = await told(PERSON_CHAT, new RegExp(`^<b>${ADMIN2} đã trở thành quản trị viên</b>`), sentBefore);
  check(message && message.text.includes(`Do quản trị viên ${adminName} thực hiện`), `a new administrator is told, and by whom (${(message?.text || '').split('\n')[0]})`);
  check(await mailTo(OPS, new RegExp(`^${ADMIN2} đã trở thành quản trị viên$`), since), 'by mail too, to the addresses given');
  const second = session(LOCAL);
  check((await second('POST', '/auth/login', { username: ADMIN2, password: a2first })).ok, `${ADMIN2} signs in - the first address on record, told to nobody`);
  const outside = session(OUTSIDE);
  sentBefore = sent.length;
  check((await outside('POST', '/auth/login', { username: ADMIN2, password: a2first })).ok, `${ADMIN2} signs in again, from ${OWN_IP}`);
  message = await told(PERSON_CHAT, new RegExp(`Có đăng nhập mới vào tài khoản quản trị ${ADMIN2}`), sentBefore);
  check(message && message.text.includes(`Từ địa chỉ ${OWN_IP}`) && message.text.includes('notify-check'),
    'a sign-in to an administrator account from a new address is told, with the address and the browser');
  sentBefore = sent.length;
  answer = await admin('POST', `/users/${admin2Id}/password`, { password: `A2-${randomBytes(12).toString('base64url')}` });
  message = await told(PERSON_CHAT, new RegExp(`Đã đổi mật khẩu: ${ADMIN2}`), sentBefore);
  check(answer.ok && message?.text.includes(`Do quản trị viên ${adminName} thực hiện, từ địa chỉ`), `its password changed by another administrator is told, and by whom (${short(answer)})`);

  // ---------------------------------------------------------------- a customer's own business
  sentBefore = sent.length;
  since = mails.length;
  const customerOutside = session(OUTSIDE);
  check((await customerOutside('POST', '/auth/login', { username: NAME, password: first })).ok, `the customer signs in from ${OWN_IP} too`);
  const secondPassword = `N2-${randomBytes(12).toString('base64url')}`;
  answer = await admin('POST', `/users/${userId}/password`, { password: secondPassword });
  await sleep(4000);
  check(answer.ok && !sent.slice(sentBefore).some((s) => s.text.includes(NAME)) && !mails.slice(since).some((m) => read(m).subject.includes(NAME)),
    'a customer\'s sign-in from a new address, and its password changed, are told to nobody');

  // ---------------------------------------------------------------- a customer's backup that fails, in English
  answer = await admin('PUT', '/notifications/settings', { language: 'en' });
  check(answer.ok && answer.json.language === 'en', 'messages are to be written in English');
  targetId = (await admin('POST', '/maintenance/sftp-targets', { name: 'notify-check', host: '127.0.0.1', port: 1, username: 'nobody', password: 'x', private_key: null, remote_path: '/tmp/notify-check' })).json?.id;
  scheduleId = (await admin('POST', '/maintenance/backup-schedules', { user_ids: [userId], schedule: '0 4 * * *', target_id: targetId, name_style: 'timestamp', retention: 1 })).json?.id;
  sentBefore = sent.length;
  since = mails.length;
  answer = await admin('POST', `/maintenance/backup-schedules/${scheduleId}/run`);
  check(answer.ok, `a schedule whose destination cannot be reached is run (${short(answer)})`);
  message = await told(PERSON_CHAT, new RegExp(`^<b>Scheduled backup failed: #${scheduleId}`), sentBefore);
  check(message && message.text.includes(`${NAME}: `), `the administrators are told, in English, which account was not backed up (${(message?.text || '').split('\n')[3] || ''})`);
  check(await mailTo(ONCALL, new RegExp(`^Scheduled backup failed: #${scheduleId}`), since), 'by mail too');
  await admin('PUT', '/notifications/settings', { language: 'vi' });

  // ---------------------------------------------------------------- malware on the customer's website
  const site = (await admin('POST', '/websites', { domain: DOMAIN, app_type: 'static', owner_id: userId })).json;
  siteId = site?.id;
  const eicar = `${site.root_path}/eicar.php`;
  writeFileSync(eicar, EICAR);
  const owner = statSync(site.root_path);
  chownSync(eicar, owner.uid, owner.gid);
  sentBefore = sent.length;
  since = mails.length;
  const started = await admin('POST', '/malware/run', { website_id: siteId });
  const job = await until(async () => {
    const j = (await admin('GET', `/malware/jobs/${started.json?.job_id}`)).json;
    return j && !['queued', 'running'].includes(j.status) ? j : null;
  }, 600);
  check(job?.status === 'infected' && job?.quarantined === 1, `a scan finds eicar.php and sets it aside (${job?.status} q=${job?.quarantined})`);
  message = await told(PERSON_CHAT, new RegExp(`Phát hiện mã độc trên ${escape(DOMAIN)}`), sentBefore);
  check(message && message.text.includes('đã chuyển 1 tệp vào khu cô lập') && message.text.includes('eicar.php'), 'the administrators are told what was found and set aside');
  check(await mailTo(OPS, new RegExp(`^Phát hiện mã độc trên ${escape(DOMAIN)}$`), since), 'by mail too');

  // ---------------------------------------------------------------- an event turned off
  answer = await admin('PUT', '/notifications/settings', { events: { security: false } });
  check(answer.ok && answer.json.events.find((e) => e.key === 'security')?.on === false, '"Changes to an administrator account" turned off');
  sentBefore = sent.length;
  await admin('POST', `/users/${admin2Id}/password`, { password: `A3-${randomBytes(12).toString('base64url')}` });
  await sleep(4000);
  check(!sent.slice(sentBefore).some((s) => s.text.includes(`Đã đổi mật khẩu: ${ADMIN2}`)), 'and not told the next time');
  answer = await admin('PUT', '/notifications/settings', { events: { nosuch: true } });
  check(answer.status === 400, `an event that is not one is refused (${short(answer)})`);
  await admin('PUT', '/notifications/settings', { events: { security: true } });

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
  check(await told(PERSON_CHAT, new RegExp(`Dịch vụ đã dừng: ${redis}`)), 'stopped at the second look: told');
  const tally = sent.filter((s) => /đã dừng/.test(s.text)).length;
  await checks();
  await sleep(1000);
  check(sent.filter((s) => /đã dừng/.test(s.text)).length === tally, 'and told once');
  run('systemctl', ['start', redis]);
  await checks();
  check(await told(PERSON_CHAT, new RegExp(`Dịch vụ đã chạy lại: ${redis}`)), 'running again: told');

  // ---------------------------------------------------------------- the log, and who was never written to
  const log = ((await admin('GET', '/notifications/log')).json?.items || []).filter((r) => r.id > logStart);
  const events = new Set(log.map((r) => r.event));
  for (const e of ['test', 'security', 'sign_in', 'backup_failed', 'malware', 'service_down']) {
    check(events.has(e), `the log has ${e}`);
  }
  const unsent = log.filter((r) => r.status !== 'sent');
  check(unsent.length === 0, `every one of them sent${unsent.length ? `: ${JSON.stringify(unsent.map((r) => [r.event, r.channel, r.target, r.detail]))}` : ''}`);
  check(!mails.some((m) => m.to.some((to) => to.startsWith(`${NAME}@`))) && !log.some((r) => r.target.startsWith(`${NAME}@`)),
    'and the customer was never written to');
} catch (err) {
  ok = false;
  console.log(`FAIL  ${err.stack || err.message}`);
} finally {
  if (scheduleId) await admin('DELETE', `/maintenance/backup-schedules/${scheduleId}`);
  if (targetId) await admin('DELETE', `/maintenance/sftp-targets/${targetId}`);
  if (siteId) await admin('DELETE', `/websites/${siteId}`);
  if (userId) await admin('DELETE', `/users/${userId}`);
  if (admin2Id) await admin('DELETE', `/users/${admin2Id}`);
  await admin('DELETE', '/notifications/smtp');
  await admin('DELETE', '/notifications/telegram');
  if (Object.keys(DEFAULTS).length) await admin('PUT', '/notifications/settings', { language: 'vi', events: DEFAULTS });
  pointPanel(false);
  smtp.close();
  telegram.server.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
