// Passkeys, end to end, with Chromium's virtual authenticator.
//
//     node passkeys.mjs [out-dir]        (LOGIN_FILE: the administrator's)
//
// WebAuthn wants a secure page with a domain name - never an IP address, the
// way the panel under test is reached. So this opens a TCP relay on the
// loopback to PANEL_BASE and runs the user's pages at https://localhost:<port>,
// where --allow-insecure-localhost makes the panel's self-signed certificate
// acceptable for localhost only. PANEL_BASE itself, by IP, is "somewhere the
// passkeys do not work".
//
// A throwaway user "uiprobe2" is made (a random password, never printed), and
// with no authenticator app:
//   - the Security page asks for the current password to add a passkey, and
//     a wrong one is refused;
//   - with the right one a passkey is added, and sign-in uses it - no code
//     field, no code link;
//   - a passkey that fails says so and offers itself again, never a code;
//   - opened by IP address, the sign-in is refused and names where the
//     passkeys work, rather than letting the password through;
// then with the app on as well: a failing passkey falls back to the code, and
// turning the app off keeps the passkey; removing it asks for the password;
// an administrator's 2FA reset takes passkeys too; wrong passwords for a new
// passkey are cut off. The user is deleted at the end, whatever happened.
import { chromium } from 'playwright';
import { createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import net from 'node:net';
import { BASE, logIn } from './capture.mjs';

const OUT = process.argv[2] || '/root/ui-audit/passkeys';
const USERNAME = 'uiprobe2';
const PASSWORD = `P-${randomBytes(18).toString('base64url')}`;
mkdirSync(OUT, { recursive: true });

let ok = true;
const check = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); ok &&= !!cond; };

function base32(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of text.replace(/=+$/, '').toUpperCase()) {
    const v = alphabet.indexOf(c);
    if (v >= 0) bits += v.toString(2).padStart(5, '0');
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
// RFC 6238, as pyotp and the panel do it: SHA-1, 30 seconds, 6 digits.
function totp(secret) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac('sha1', base32(secret)).update(counter).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

// ---------------------------------------------------------------- the relay
const target = new URL(BASE);
const relayTo = (client) => {
  const upstream = net.connect(Number(target.port || 443), target.hostname);
  client.pipe(upstream).pipe(client);
  client.on('error', () => upstream.destroy());
  upstream.on('error', () => client.destroy());
};
const relay4 = net.createServer(relayTo);
await new Promise((resolve) => relay4.listen({ port: 0, host: '127.0.0.1' }, resolve));
const PORT = relay4.address().port;
// Chromium may try ::1 first for localhost; the same port there, if it has one.
const relay6 = net.createServer(relayTo);
await new Promise((resolve) => { relay6.once('error', resolve); relay6.listen({ port: PORT, host: '::1' }, resolve); });
const LOCAL = `https://localhost:${PORT}`;

const browser = await chromium.launch({ args: ['--allow-insecure-localhost'] });
const csrfOf = async (context) => (await context.cookies()).find((c) => c.name === 'snpanel_csrf')?.value;
const api = async (context, base, method, path, data) => {
  const csrf = await csrfOf(context);
  return context.request.fetch(`${base}/api${path}`, { method, data, headers: csrf ? { 'X-CSRF-Token': csrf } : {} });
};

const admin = await browser.newContext({ ignoreHTTPSErrors: true });
await logIn(admin);
const probeOf = async () => {
  const users = await (await api(admin, BASE, 'GET', '/users?usage=0')).json();
  return (users.items || users).find((u) => u.username === USERNAME);
};
async function removeProbe() {
  const probe = await probeOf();
  if (probe) await api(admin, BASE, 'DELETE', `/users/${probe.id}`);
}

await removeProbe();
const created = await api(admin, BASE, 'POST', '/users', {
  username: USERNAME, email: `${USERNAME}@example.invalid`, password: PASSWORD,
  role: 'end_user', package_id: null, website_limit: 1, storage_limit_mb: 100,
});
check(created.ok(), `created ${USERNAME} (HTTP ${created.status()})`);

const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: 'en-US', timezoneId: 'Asia/Ho_Chi_Minh' });
await context.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
const page = await context.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));
page.on('dialog', (d) => d.accept());
const listed = async () => (await api(context, LOCAL, 'GET', '/auth/passkeys')).json();

try {
  const login = await context.request.post(`${LOCAL}/api/auth/login`, { form: { username: USERNAME, password: PASSWORD } });
  check(login.status() === 200, `${USERNAME} signs in with a password at ${LOCAL} (HTTP ${login.status()})`);

  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  // ------------------------------------------ added with no authenticator app
  await page.goto(`${LOCAL}/security`, { waitUntil: 'networkidle' });
  const form = page.locator('.passkey-form');
  await form.waitFor({ timeout: 15000 });
  check(await form.getByLabel('Current password').isVisible() && await form.getByLabel('Authenticator code').count() === 0,
    'with the app off, adding a passkey asks for the current password and no code');
  check(await page.locator('.passkey-backup').isVisible(), 'and says how to keep a way back');
  await form.getByLabel('Name').fill('Virtual key');
  await form.getByLabel('Current password').fill('not the password');
  await form.getByRole('button', { name: 'Add a passkey' }).click();
  await page.getByText('Current password is incorrect').first().waitFor({ timeout: 10000 });
  check((await listed()).items.length === 0, 'a wrong password makes no passkey, and says why');
  await form.getByLabel('Current password').fill(PASSWORD);
  await form.getByRole('button', { name: 'Add a passkey' }).click();
  await page.locator('.passkey-table tbody tr', { hasText: 'Virtual key' }).waitFor({ timeout: 20000 });
  let keys = await listed();
  check(keys.items.length === 1 && keys.items[0].rp_id === 'localhost' && !keys.totp_enabled,
    `the right one adds it, for localhost, with the app still off (${JSON.stringify(keys.items.map((p) => [p.name, p.rp_id]))})`);
  await page.screenshot({ path: `${OUT}/security-passkey-only-light-en.png`, fullPage: true });

  // ------------------------------------------ signing in with it: nothing to type
  const signIn = async (base = LOCAL) => {
    await context.clearCookies();
    await page.goto(`${base}/`, { waitUntil: 'networkidle' });
    await page.getByLabel('Username').fill(USERNAME);
    await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Login' }).click();
  };
  await signIn();
  await page.waitForSelector('.dashboard .dash-card', { timeout: 20000 });
  keys = await listed();
  check(!!keys.items[0].last_used_at, `the passkey alone completes the sign-in (used ${keys.items[0].last_used_at})`);

  // ------------------------------------------ one that fails offers itself again
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  const real = credentials[0];
  const wrong = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const useKey = async (privateKey, bump) => {
    await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
    await cdp.send('WebAuthn.addCredential', {
      authenticatorId,
      credential: { credentialId: real.credentialId, isResidentCredential: false, rpId: 'localhost', privateKey, signCount: real.signCount + bump },
    });
  };
  await useKey(wrong, 10);
  await signIn();
  await page.locator('.login-passkey-failed').waitFor({ timeout: 20000 });
  await page.screenshot({ path: `${OUT}/login-passkey-only-failed-light-en.png`, fullPage: true });
  check(await page.getByLabel('Authentication code').count() === 0
    && await page.getByRole('button', { name: 'Use the authenticator code instead' }).count() === 0
    && await page.getByRole('button', { name: 'Login' }).count() === 0,
  'a failing passkey asks for no code: there is none');
  await useKey(real.privateKey, 20);
  await page.getByRole('button', { name: 'Try the passkey again' }).click();
  await page.waitForSelector('.dashboard .dash-card', { timeout: 20000 });
  check(true, '"Try the passkey again" signs in once the passkey works');

  // ------------------------------------------ by IP address: refused, with where
  const byIp = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  await byIp.addInitScript(() => { try { localStorage.setItem('snpanel-theme', 'light'); localStorage.setItem('snpanel-locale', 'en'); } catch {} });
  const ipPage = await byIp.newPage();
  await ipPage.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await ipPage.getByLabel('Username').fill(USERNAME);
  await ipPage.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await ipPage.getByRole('button', { name: 'Login' }).click();
  const refusal = ipPage.getByText(/passkeys work only at localhost/);
  await refusal.waitFor({ timeout: 15000 });
  await ipPage.screenshot({ path: `${OUT}/login-by-ip-refused-light-en.png`, fullPage: true });
  const direct = await byIp.request.post(`${BASE}/api/auth/login`, { form: { username: USERNAME, password: PASSWORD, otp: '123456' } });
  check(await refusal.isVisible() && direct.status() === 403 && !(await byIp.cookies()).some((c) => c.name === 'snpanel_session'),
    `by IP address the sign-in is refused, naming localhost - a code sent anyway too (HTTP ${direct.status()})`);
  await byIp.close();

  // ------------------------------------------ the app as well: the code falls back
  await page.goto(`${LOCAL}/security`, { waitUntil: 'networkidle' });
  const setup = await (await api(context, LOCAL, 'POST', '/auth/2fa/setup', { current_password: PASSWORD })).json();
  const secret = setup.secret;
  const enabled = await api(context, LOCAL, 'POST', '/auth/2fa/enable', { code: totp(secret) });
  check(enabled.ok() && !!secret, `the authenticator app is on as well (HTTP ${enabled.status()})`);
  await useKey(wrong, 30);
  await signIn();
  await page.locator('.login-passkey-failed').waitFor({ timeout: 20000 });
  await page.getByLabel('Authentication code').fill(totp(secret));
  await page.getByRole('button', { name: 'Login' }).click();
  await page.waitForSelector('.dashboard .dash-card', { timeout: 20000 });
  check(true, 'with the app on, a failing passkey falls back to the code, which signs in');
  await useKey(real.privateKey, 40);

  const off = await api(context, LOCAL, 'POST', '/auth/2fa/disable', { current_password: PASSWORD, code: totp(secret) });
  keys = await listed();
  check(off.ok() && keys.items.length === 1 && !keys.totp_enabled,
    `turning the app off keeps the passkey (HTTP ${off.status()}, ${keys.items.length} left)`);

  // ------------------------------------------ removing it takes the password
  await page.goto(`${LOCAL}/security`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: 'Remove Virtual key' }).click();
  const removal = page.locator('.passkey-remove');
  await removal.waitFor({ timeout: 10000 });
  check(/last one/.test(await removal.textContent()), 'removing the last one says sign-in will then take only the password');
  await removal.getByLabel('Current password').fill('not the password');
  await removal.getByRole('button', { name: 'Remove' }).click();
  await page.getByText('Current password is incorrect').first().waitFor({ timeout: 10000 });
  check((await listed()).items.length === 1, 'a wrong password removes nothing');
  await page.screenshot({ path: `${OUT}/security-remove-light-en.png`, fullPage: true });
  await removal.getByLabel('Current password').fill(PASSWORD);
  await removal.getByRole('button', { name: 'Remove' }).click();
  await page.locator('.passkey-table').waitFor({ state: 'detached', timeout: 15000 });
  check((await listed()).items.length === 0, 'the right one removes it');

  // ------------------------------------------ an administrator's reset takes passkeys
  await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
  await page.locator('.passkey-form').getByLabel('Name').fill('Second key');
  await page.locator('.passkey-form').getByLabel('Current password').fill(PASSWORD);
  await page.locator('.passkey-form').getByRole('button', { name: 'Add a passkey' }).click();
  await page.locator('.passkey-table tbody tr', { hasText: 'Second key' }).waitFor({ timeout: 20000 });
  const before = await probeOf();
  const reset = await api(admin, BASE, 'POST', `/users/${before.id}/2fa/reset`);
  const after = await probeOf();
  check(before.passkeys === 1 && reset.ok() && after.passkeys === 0 && !after.totp_enabled,
    `the Users list counts the passkey, and a 2FA reset takes it (${before.passkeys} -> ${after.passkeys}, HTTP ${reset.status()})`);

  // ------------------------------------------ guessing the password is cut off
  const again = await context.request.post(`${LOCAL}/api/auth/login`, { form: { username: USERNAME, password: PASSWORD } });
  check(again.status() === 200, 'signed in again after the reset');
  const statuses = [];
  for (let i = 0; i < 12; i += 1) {
    const res = await api(context, LOCAL, 'POST', '/auth/passkeys/register/options', { current_password: `wrong-${i}` });
    statuses.push(res.status());
    if (res.status() === 429) break;
  }
  check(statuses.at(-1) === 429 && statuses.slice(0, -1).every((s) => s === 401),
    `wrong passwords for a new passkey are cut off (${statuses.join(' ')})`);

  check(errors.length === 0, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (err) {
  // Where it stopped, for whoever reads the failure: the screen and its words.
  ok = false;
  console.log(`FAIL  ${err.message.split('\n')[0]}`);
  await page.screenshot({ path: `${OUT}/stopped-here.png`, fullPage: true }).catch(() => {});
  console.log(`      the page said: ${(await page.locator('body').innerText().catch(() => '')).replace(/\s+/g, ' ').slice(0, 400)}`);
} finally {
  await removeProbe();
  await browser.close();
  relay4.close();
  relay6.close();
}
console.log(ok ? 'PASS' : 'FAIL');
process.exit(ok ? 0 : 1);
