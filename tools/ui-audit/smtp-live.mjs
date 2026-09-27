// STARTTLS and implicit TLS against a real mail server, without signing in
// or sending anything: the server refuses the sender, which it can only say
// after the handshake and a second EHLO over TLS.
//
//     node smtp-live.mjs [host]        (on the box, as root; smtp.gmail.com)
import https from 'node:https';
import { readFileSync } from 'node:fs';

const HOST = process.argv[2] || 'smtp.gmail.com';
const jar = new Map();
function api(method, path, body) {
  const headers = {};
  let payload;
  if (path === '/auth/login') { headers['Content-Type'] = 'application/x-www-form-urlencoded'; payload = new URLSearchParams(body).toString(); }
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  if (payload !== undefined) headers['Content-Length'] = Buffer.byteLength(payload);
  headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  if (method !== 'GET' && jar.get('snpanel_csrf')) headers['X-CSRF-Token'] = jar.get('snpanel_csrf');
  return new Promise((resolve, reject) => {
    const req = https.request(new URL(`https://127.0.0.1:2222/api${path}`), { method, headers, rejectUnauthorized: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        for (const c of res.headers['set-cookie'] || []) { const [pair] = c.split(';'); const i = pair.indexOf('='); jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim()); }
        resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}
const login = readFileSync('/root/login.txt', 'utf8');
await api('POST', '/auth/login', { username: /^User: (.+)$/m.exec(login)[1].trim(), password: /^Password: (.+)$/m.exec(login)[1].trim() });
const addons = JSON.parse((await api('GET', '/addons')).text);
const was = addons.items.find((a) => a.slug === 'notifications')?.installed;
if (!was) await api('POST', '/addons/notifications/install');
for (const [security, port] of [['starttls', 587], ['tls', 465]]) {
  await api('PUT', '/notifications/smtp', { host: HOST, port, security, username: '', password: '', from_address: 'check@example.com', from_name: 'check' });
  await new Promise((r) => setTimeout(r, 5500));
  const answer = await api('POST', '/notifications/test', { channel: 'email', to: 'nobody@example.com' });
  console.log(`${security}:${port} -> ${answer.status} ${answer.text.slice(0, 220)}`);
}
await api('DELETE', '/notifications/smtp');
if (!was) await api('POST', '/addons/notifications/uninstall');
